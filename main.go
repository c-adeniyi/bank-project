package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Account struct {
	Name         string
	Username     string
	Email        string
	PasswordHash string
	PINHash      string
	Verified     bool
	AccountNo    string
	Currency     string
	Balance      float64
}

type Transaction struct {
	Type     string
	Amount   float64
	Currency string
	Details  string
	Date     string
}

type RateResponse struct {
	Rate float64 `json:"rate"`
}

type SearchResult struct {
	Name      string `json:"name"`
	AccountNo string `json:"accountNo"`
	Currency  string `json:"currency"`
}

var (
	accounts     []Account
	transactions = make(map[string][]Transaction)
	sessions     = make(map[string]string)

	verificationTokens = make(map[string]string) // token -> username
	resetTokens        = make(map[string]string) // token -> username
	captchas           = make(map[string]captchaChallenge)
	loginChallenges    = make(map[string]loginChallenge)

	mu sync.Mutex
)

type captchaChallenge struct {
	Question string
	Answer   string
	Expires  time.Time
	ImageSVG string
}

type loginChallenge struct {
	Username string
	Code     string
	Expires  time.Time
	Attempts int
}

var currencies = []string{
	"USD",
	"EUR",
	"GBP",
	"JPY",
	"NGN",
	"CAD",
	"AUD",
	"CHF",
}

// ----------------------------------------------------
// PERSISTENCE
//
// The old version of this app kept everything in plain
// Go variables (accounts, transactions). That data only
// ever existed in the memory of ONE running process, so:
//   - if the host restarted/redeployed the process, every
//     account/transaction vanished and a brand new batch
//     of 1,000 test accounts was generated
//   - if you ever ran more than one instance of the
//     server (e.g. behind a load balancer), each instance
//     had its own separate copy of "accounts", so an
//     account created on instance A was invisible to
//     instance B
//
// This adds a simple JSON-file store so accounts and
// transactions survive restarts. Every mutation is saved
// to disk immediately, and the whole state is reloaded
// on startup instead of always generating fresh test data.
//
// NOTE: this still assumes a single running instance with
// a persistent disk. If you deploy multiple instances
// behind a load balancer, you'll need a real shared
// database (SQLite on a shared volume, or Postgres/MySQL)
// instead of a local JSON file — happy to do that next if
// that's how you're hosting this.
// ----------------------------------------------------

const dataFile = "data.json"

type PersistedState struct {
	Accounts     []Account                `json:"accounts"`
	Transactions map[string][]Transaction `json:"transactions"`
}

// persistLocked writes the current state to disk.
// Caller MUST already hold mu before calling this.
func persistLocked() {
	state := PersistedState{
		Accounts:     accounts,
		Transactions: transactions,
	}

	data, err := json.MarshalIndent(state, "", "  ")

	if err != nil {
		fmt.Println("WARNING: failed to encode state:", err)
		return
	}

	tmpFile := dataFile + ".tmp"

	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		fmt.Println("WARNING: failed to write state file:", err)
		return
	}

	// Write-then-rename so a crash mid-write can never
	// leave data.json half-written/corrupted.
	if err := os.Rename(tmpFile, dataFile); err != nil {
		fmt.Println("WARNING: failed to save state file:", err)
	}
}

// loadState loads accounts/transactions from disk if a
// data file already exists. Returns true if it loaded
// existing data, false if there was nothing to load.
func loadState() bool {
	data, err := os.ReadFile(dataFile)

	if err != nil {
		// No file yet (first run) — nothing to load.
		return false
	}

	var state PersistedState

	if err := json.Unmarshal(data, &state); err != nil {
		fmt.Println("WARNING: could not parse data.json, ignoring it:", err)
		return false
	}

	// Migrate accounts created by older versions of the demo.
	for i := range state.Accounts {
		if state.Accounts[i].Email == "" {
			state.Accounts[i].Email = state.Accounts[i].Username + "@example.com"
			state.Accounts[i].Verified = true
		}
	}

	accounts = state.Accounts

	if state.Transactions != nil {
		transactions = state.Transactions
	} else {
		transactions = make(map[string][]Transaction)
	}

	return true
}

// ----------------------------------------------------
// EMAIL + CAPTCHA + 2FA HELPERS
// ----------------------------------------------------
func emailConfigured() bool {
	return os.Getenv("RESEND_API_KEY") != "" && os.Getenv("EMAIL_FROM") != ""
}

func sendEmail(to, subject, body string) error {
	if !emailConfigured() {
		return fmt.Errorf("email service is not configured")
	}
	payload := map[string]interface{}{"from": os.Getenv("EMAIL_FROM"), "to": []string{to}, "subject": subject, "text": body}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("RESEND_API_KEY"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("email provider returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}
func randomOTP() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return fmt.Sprintf("%06d", n%1000000)
}

func newCaptcha() string {
	id := randomToken()
	if id == "" {
		return ""
	}
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 6)
	r := make([]byte, 6)
	if _, err := rand.Read(r); err != nil {
		return ""
	}
	for i := range raw {
		raw[i] = chars[int(r[i])%len(chars)]
	}
	answer := string(raw)
	var svg strings.Builder
	svg.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="260" height="82"><rect width="260" height="82" rx="10" fill="#f1f5f9"/>`)
	for i := 0; i < 18; i++ {
		x := int(r[i%6])*4 + i*7
		y := int(r[(i+2)%6]) % 82
		x2 := (x + 50 + i*9) % 260
		y2 := (y + 23 + i*5) % 82
		svg.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#64748b" stroke-width="1" opacity=".35"/>`, x%260, y, x2, y2))
	}
	for i, c := range raw {
		x := 18 + i*39
		y := 54 + int(r[(i+1)%6])%10
		rot := -18 + int(r[(i+3)%6])%37
		svg.WriteString(fmt.Sprintf(`<text x="%d" y="%d" transform="rotate(%d %d %d)" font-family="Arial" font-size="34" font-weight="700" fill="#1e293b">%c</text>`, x, y, rot, x, y, c))
	}
	for i := 0; i < 35; i++ {
		x := int(r[i%6])*5 + i*3
		y := int(r[(i+1)%6]) % 82
		svg.WriteString(fmt.Sprintf(`<circle cx="%d" cy="%d" r="1.4" fill="#334155" opacity=".45"/>`, x%260, y))
	}
	svg.WriteString(`</svg>`)
	mu.Lock()
	captchas[id] = captchaChallenge{Question: "Enter the 6 characters shown in the image.", Answer: answer, Expires: time.Now().Add(5 * time.Minute), ImageSVG: svg.String()}
	mu.Unlock()
	return id
}
func captchaHTML(id string) string {
	mu.Lock()
	c, ok := captchas[id]
	mu.Unlock()
	if !ok {
		return ""
	}
	return fmt.Sprintf(`<div class="info"><strong>Security check</strong><p>%s</p><img src="/captcha-image?id=%s" alt="CAPTCHA" style="display:block;width:260px;height:82px;border:1px solid #cbd5e1;border-radius:10px;margin:8px 0"><a href="#" onclick="location.reload();return false">Get a new CAPTCHA</a></div><input type="text" name="captcha" maxlength="6" autocomplete="off" placeholder="Enter the characters" required><input type="hidden" name="captchaID" value="%s">`, template.HTMLEscapeString(c.Question), template.HTMLEscapeString(id), template.HTMLEscapeString(id))
}
func captchaImage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	mu.Lock()
	c, ok := captchas[id]
	mu.Unlock()
	if !ok || time.Now().After(c.Expires) {
		http.Error(w, "CAPTCHA expired", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, c.ImageSVG)
}
func verifyCaptcha(id, answer string) bool {
	mu.Lock()
	defer mu.Unlock()
	c, ok := captchas[id]
	if !ok || time.Now().After(c.Expires) {
		delete(captchas, id)
		return false
	}
	delete(captchas, id)
	return strings.EqualFold(strings.TrimSpace(answer), c.Answer)
}
func baseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("APP_BASE_URL")), "/"); v != "" {
		return v
	}
	if v := strings.TrimRight(os.Getenv("RENDER_EXTERNAL_URL"), "/"); v != "" {
		return v
	}
	return "http://localhost:8080"
}
func renderError(w http.ResponseWriter, title, message, backURL string) {
	fmt.Fprintln(w, pageStart(title))
	fmt.Fprintf(w, `<div class="container"><div class="card"><div class="error">%s</div><a href="%s"><button>Try Again</button></a></div></div></body></html>`, template.HTMLEscapeString(message), backURL)
}

// ----------------------------------------------------
// PASSWORD
// ----------------------------------------------------
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", h)
}
func validPassword(password string) bool {
	if len(password) < 10 {
		return false
	}
	var u, l, n, s bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			u = true
		case c >= 'a' && c <= 'z':
			l = true
		case c >= '0' && c <= '9':
			n = true
		default:
			s = true
		}
	}
	return u && l && n && s
}
func validPIN(pin string) bool {
	if len(pin) != 4 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func generateAccountNumber() string {
	for {
		b := make([]byte, 8)

		if _, err := rand.Read(b); err != nil {
			continue
		}

		number := uint64(0)

		for _, x := range b {
			number = number*256 + uint64(x)
		}

		number = 1000000000 + number%9000000000
		result := strconv.FormatUint(number, 10)

		exists := false

		for _, account := range accounts {
			if account.AccountNo == result {
				exists = true
				break
			}
		}

		if !exists {
			return result
		}
	}
}

// ----------------------------------------------------
// SESSIONS
// ----------------------------------------------------

func createSession(username string) string {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return ""
	}

	sessionID := fmt.Sprintf("%x", b)
	sessions[sessionID] = username

	return sessionID
}

func getLoggedInUser(r *http.Request) string {
	cookie, err := r.Cookie("session")

	if err != nil {
		return ""
	}

	mu.Lock()
	defer mu.Unlock()

	return sessions[cookie.Value]
}

// ----------------------------------------------------
// ACCOUNT SEARCH
// ----------------------------------------------------

func findAccount(username string) *Account {
	for i := range accounts {
		if accounts[i].Username == username {
			return &accounts[i]
		}
	}

	return nil
}

func findAccountByNumber(number string) *Account {
	for i := range accounts {
		if accounts[i].AccountNo == number {
			return &accounts[i]
		}
	}

	return nil
}

// ----------------------------------------------------
// CURRENCY
// ----------------------------------------------------

func getExchangeRate(from, to string) (float64, error) {
	if from == to {
		return 1, nil
	}

	url := fmt.Sprintf(
		"https://api.frankfurter.dev/v2/rate/%s/%s",
		from,
		to,
	)

	response, err := http.Get(url)

	if err != nil {
		return 0, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("exchange rate unavailable")
	}

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return 0, err
	}

	var data RateResponse

	if err := json.Unmarshal(body, &data); err != nil {
		return 0, err
	}

	if data.Rate <= 0 {
		return 0, fmt.Errorf("invalid exchange rate")
	}

	return data.Rate, nil
}

// ----------------------------------------------------
// PAGE HEADER
// ----------------------------------------------------

func pageStart(title string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>

<meta name="viewport" content="width=device-width, initial-scale=1">

<title>%s - Caleb's City Mall Bank</title>

<style>

* {
	box-sizing: border-box;
}

body {
	margin: 0;
	font-family: Arial, sans-serif;
	background: #eef2ff;
	color: #222;
}

.navbar {
	background: linear-gradient(135deg, #5429c7, #1769e0);
	color: white;
	padding: 18px 6%%;
	display: flex;
	justify-content: space-between;
	align-items: center;
	flex-wrap: wrap;
}

.logo {
	font-size: 21px;
	font-weight: bold;
}

.navbar a {
	color: white;
	text-decoration: none;
	margin-left: 15px;
}

.container {
	max-width: 1000px;
	margin: 35px auto;
	padding: 20px;
}

.card {
	background: white;
	padding: 28px;
	margin-bottom: 25px;
	border-radius: 16px;
	box-shadow: 0 5px 20px rgba(0,0,0,.08);
}

.hero {
	background: linear-gradient(135deg, #5429c7, #1769e0);
	color: white;
	padding: 35px;
	border-radius: 18px;
	margin-bottom: 25px;
}

.balance {
	font-size: 36px;
	font-weight: bold;
}

.account-number {
	background: #eef2ff;
	padding: 15px;
	border-radius: 10px;
	font-size: 19px;
	font-weight: bold;
	letter-spacing: 2px;
}

.grid {
	display: grid;
	grid-template-columns: repeat(2, 1fr);
	gap: 20px;
}

input,
select {
	width: 100%%;
	padding: 13px;
	margin: 8px 0 15px;
	border: 1px solid #ccd2e0;
	border-radius: 8px;
	font-size: 15px;
}

button {
	background: linear-gradient(135deg, #5429c7, #1769e0);
	color: white;
	border: none;
	padding: 13px 20px;
	border-radius: 8px;
	cursor: pointer;
	font-size: 15px;
}

button:hover {
	opacity: .9;
}

.success {
	background: #dcfce7;
	color: #166534;
	padding: 15px;
	border-radius: 8px;
	margin-bottom: 15px;
}

.error {
	background: #fee2e2;
	color: #991b1b;
	padding: 15px;
	border-radius: 8px;
	margin-bottom: 15px;
}

.info {
	background: #dbeafe;
	color: #1e40af;
	padding: 15px;
	border-radius: 8px;
	margin-bottom: 15px;
}

.recipient {
	background: #eef2ff;
	padding: 15px;
	border-radius: 10px;
	margin-bottom: 15px;
}

.suggestion {
	padding: 12px;
	border-radius: 8px;
	cursor: pointer;
}

.suggestion:hover {
	background: #dbeafe;
}

.transaction {
	padding: 18px 5px;
	border-bottom: 1px solid #ddd;
}

.sent {
	color: #dc2626;
}

.received {
	color: #16a34a;
}

.withdrawal {
	color: #d97706;
}

@media (max-width: 700px) {

	.grid {
		grid-template-columns: 1fr;
	}

	.navbar {
		flex-direction: column;
		gap: 12px;
	}

	.navbar a {
		margin-left: 5px;
	}

}

</style>

</head>

<body>

<div class="navbar">

<div class="logo">
🏦 Caleb's City Mall Bank
</div>

<div>
<a href="/">Home</a>
<a href="/send">Send</a>
<a href="/withdraw">Withdraw</a>
<a href="/transactions">Transactions</a>
<a href="/profile">Profile</a>
<a href="/change-password">Password</a>
<a href="/change-currency">Currency</a>
<a href="/logout">Logout</a>
</div>

</div>
`, title)
}

// ----------------------------------------------------
// HOME
// ----------------------------------------------------

func home(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {
		loginPage(w, "")
		return
	}

	mu.Lock()

	account := findAccount(username)

	if account == nil {
		mu.Unlock()
		loginPage(w, "")
		return
	}

	name := account.Name
	number := account.AccountNo
	currency := account.Currency
	balance := account.Balance

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Dashboard"))

	fmt.Fprintf(w, `

<div class="container">

<div class="hero">

<h1>Welcome, %s! 👋</h1>

<p>Available Balance</p>

<div class="balance">
%.2f %s
</div>

</div>

<div class="grid">

<div class="card">

<h2>💳 Account</h2>

<p>Account Number:</p>

<div class="account-number">
%s
</div>

<p>Currency: <strong>%s</strong></p>

</div>

<div class="card">

<h2>📤 Send Money</h2>

<p>Send money in any supported currency.</p>

<a href="/send">
<button>Send Money</button>
</a>

</div>

<div class="card">

<h2>💵 Withdraw</h2>

<p>Withdraw money from your account.</p>

<a href="/withdraw">
<button>Withdraw</button>
</a>

</div>

<div class="card">

<h2>📜 Transactions</h2>

<p>View all your banking activity.</p>

<a href="/transactions">
<button>View Transactions</button>
</a>

</div>

</div>

</div>

</body>
</html>

`,
		template.HTMLEscapeString(name),
		balance,
		currency,
		number,
		currency,
	)
}

// ----------------------------------------------------
// LOGIN PAGE
// ----------------------------------------------------

func loginPage(w http.ResponseWriter, message string) {
	captchaID := newCaptcha()

	fmt.Fprintln(w, pageStart("Login"))

	fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>Welcome Back 👋</h1>
<p>Sign in to Caleb's City Mall Bank.</p>

%s

<form action="/login" method="POST">

<label>Email</label>
<input
type="email"
name="email"
required
autocomplete="email"
>

<label>Transaction PIN</label>
<input type="password" name="pin" inputmode="numeric" maxlength="4" minlength="4" pattern="[0-9]{4}" required autocomplete="off">
<p><small>Your 4-digit transaction PIN is required before sending money.</small></p>

<label>Password</label>
<div style="display:flex; gap:8px;">
<input
id="loginPassword"
type="password"
name="password"
required
autocomplete="current-password"
>
<button type="button" class="show-password" onclick="toggleField('loginPassword', this)">Show</button>
</div>

%s

<button type="submit">Sign In</button>
</form>

<p><a href="/forgot-password">Forgot your password?</a></p>
<p>Don't have an account? <a href="/register">Create an account</a></p>

</div>
</div>

<script>
function toggleField(id, button) {
	const field = document.getElementById(id);
	if (field.type === "password") {
		field.type = "text";
		button.textContent = "Hide";
	} else {
		field.type = "password";
		button.textContent = "Show";
	}
}
</script>

</body>
</html>
`, message, captchaHTML(captchaID))
}

// ----------------------------------------------------
// REGISTER
// ----------------------------------------------------

func registerPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		captchaID := newCaptcha()

		fmt.Fprintln(w, pageStart("Register"))
		fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>🏦 Create Account</h1>

<form action="/register" method="POST">

<label>Full Name</label>
<input type="text" name="name" required>

<label>Username</label>
<input type="text" name="username" required>

<label>Email</label>
<input type="email" name="email" required autocomplete="email">

<label>Password</label>
<div style="display:flex; gap:8px;">
<input id="registerPassword" type="password" name="password" required autocomplete="new-password">
<button type="button" class="show-password" onclick="toggleField('registerPassword', this)">Show</button>
</div>

<div class="info">
<strong>Password requirements:</strong>
<ul>
<li>At least 8 characters</li>
<li>1 uppercase letter</li>
<li>1 lowercase letter</li>
<li>1 number</li>
<li>1 symbol</li>
</ul>
</div>

<label>Transaction PIN</label>
<input type="password" name="pin" inputmode="numeric" maxlength="4" minlength="4" pattern="[0-9]{4}" required autocomplete="off">
<p><small>Choose a 4-digit PIN. You'll need this to send money and to sign in.</small></p>

<label>Currency</label>
<select name="currency">
<option value="USD">USD - US Dollar</option>
<option value="EUR">EUR - Euro</option>
<option value="GBP">GBP - British Pound</option>
<option value="JPY">JPY - Japanese Yen</option>
<option value="NGN">NGN - Nigerian Naira</option>
<option value="CAD">CAD - Canadian Dollar</option>
<option value="AUD">AUD - Australian Dollar</option>
<option value="CHF">CHF - Swiss Franc</option>
</select>

%s

<button type="submit">Create Account</button>
</form>

<p>Already have an account? <a href="/">Sign in</a></p>

</div>
</div>

<script>
function toggleField(id, button) {
	const field = document.getElementById(id);
	if (field.type === "password") {
		field.type = "text";
		button.textContent = "Hide";
	} else {
		field.type = "password";
		button.textContent = "Show";
	}
}
</script>

</body>
</html>
`, captchaHTML(captchaID))
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	pin := strings.TrimSpace(r.FormValue("pin"))
	currency := strings.ToUpper(r.FormValue("currency"))

	if name == "" || username == "" || email == "" || password == "" || pin == "" {
		renderError(w, "Error", "Please complete all fields.", "/register")
		return
	}

	if !strings.Contains(email, "@") {
		renderError(w, "Error", "Please enter a valid email address.", "/register")
		return
	}

	if !verifyCaptcha(r.FormValue("captchaID"), r.FormValue("captcha")) {
		renderError(w, "Security Check Failed", "Incorrect or expired CAPTCHA. Please try again.", "/register")
		return
	}

	validCurrency := false
	for _, c := range currencies {
		if currency == c {
			validCurrency = true
			break
		}
	}
	if !validCurrency {
		renderError(w, "Error", "Invalid currency.", "/register")
		return
	}

	if !validPassword(password) {
		renderError(w, "Password Error", "Password must have at least 10 characters, one uppercase letter, one lowercase letter, one number, and one symbol.", "/register")
		return
	}
	if !validPIN(pin) {
		renderError(w, "PIN Error", "Your transaction PIN must be exactly 4 digits.", "/register")
		return
	}

	mu.Lock()
	if findAccount(username) != nil {
		mu.Unlock()
		renderError(w, "Error", "That username already exists.", "/register")
		return
	}
	for _, a := range accounts {
		if strings.EqualFold(a.Email, email) {
			mu.Unlock()
			renderError(w, "Error", "That email address is already registered.", "/register")
			return
		}
	}
	accountNumber := generateAccountNumber()
	mu.Unlock()

	rate, err := getExchangeRate("USD", currency)
	if err != nil {
		renderError(w, "Error", "Unable to get the exchange rate. Please try again later.", "/register")
		return
	}

	token := randomToken()
	if token == "" {
		renderError(w, "Error", "Unable to create verification link. Please try again.", "/register")
		return
	}

	startingBalance := 1000 * rate

	// Send the verification email BEFORE saving the account. This
	// means nothing is written to storage until email delivery is
	// confirmed, so a slow, blocked, or failed send can never leave
	// behind a "stuck" unverified account that permanently occupies
	// a username/email (which is what happened before: the account
	// was saved first, then email was attempted, so a hung send left
	// a broken account sitting there that blocked re-registration but
	// could never log in).
	verifyURL := baseURL() + "/verify-email?token=" + token
	emailBody := fmt.Sprintf(
		"Hello %s,\n\nWelcome to Caleb's City Mall Bank.\n\nVerify your email by opening this link:\n%s\n\nIf you did not create this account, ignore this email.",
		name, verifyURL,
	)

	if err := sendEmail(email, "Verify your Caleb's City Mall Bank account", emailBody); err != nil {
		renderError(w, "Email Delivery Failed", "Your account could not be created because the verification email failed to send: "+err.Error(), "/register")
		return
	}

	mu.Lock()
	accounts = append(accounts, Account{
		Name:         name,
		Username:     username,
		Email:        email,
		PasswordHash: hashPassword(password),
		PINHash:      hashPassword(pin),
		Verified:     false,
		AccountNo:    accountNumber,
		Currency:     currency,
		Balance:      startingBalance,
	})
	verificationTokens[token] = username
	persistLocked()
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Verify Email"))
	fmt.Fprintf(w, `
<div class="container">
<div class="card">
<div class="success">
<h1>Account Created! 🎉</h1>
<p>We sent a verification email to <strong>%s</strong>.</p>
<p>Open the email and click the verification link before signing in.</p>
</div>
<p>Your account number:</p>
<div class="account-number">%s</div>
<p>Starting balance: <strong>%.2f %s</strong></p>
<a href="/"><button>Go to Login</button></a>
</div>
</div>
</body>
</html>
`,
		template.HTMLEscapeString(email),
		template.HTMLEscapeString(accountNumber),
		startingBalance,
		template.HTMLEscapeString(currency),
	)
}

// ----------------------------------------------------
// EMAIL VERIFICATION / FORGOT PASSWORD / RESET
// ----------------------------------------------------

func verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))

	mu.Lock()
	username := verificationTokens[token]
	account := findAccount(username)

	if token == "" || username == "" || account == nil {
		mu.Unlock()
		renderError(w, "Verification Failed", "This verification link is invalid or has already been used.", "/")
		return
	}

	account.Verified = true
	delete(verificationTokens, token)
	persistLocked()
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Email Verified"))
	fmt.Fprintln(w, `
<div class="container">
<div class="card">
<div class="success">
<h1>Email Verified! ✅</h1>
<p>Your email has been verified successfully. You can now log in.</p>
</div>
<a href="/"><button>Go to Login</button></a>
</div>
</div>
</body>
</html>
`)
}

func forgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		captchaID := newCaptcha()

		fmt.Fprintln(w, pageStart("Forgot Password"))
		fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>🔐 Forgot Password</h1>
<p>Enter the email address connected to your account.</p>

<form action="/forgot-password" method="POST">

<label>Email</label>
<input type="email" name="email" required autocomplete="email">

%s

<button type="submit">Send Reset Email</button>
</form>

<p><a href="/">Back to login</a></p>

</div>
</div>
</body>
</html>
`, captchaHTML(captchaID))
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))

	if !verifyCaptcha(r.FormValue("captchaID"), r.FormValue("captcha")) {
		renderError(w, "Security Check Failed", "Incorrect or expired CAPTCHA. Please try again.", "/forgot-password")
		return
	}

	mu.Lock()
	account := (*Account)(nil)
	for i := range accounts {
		if strings.EqualFold(accounts[i].Email, email) {
			account = &accounts[i]
			break
		}
	}

	if account == nil {
		mu.Unlock()
		// Don't reveal whether an email exists.
		fmt.Fprintln(w, pageStart("Check Your Email"))
		fmt.Fprintln(w, `
<div class="container"><div class="card">
<div class="success">
<h2>Check your email</h2>
<p>If an account exists for that email, a password-reset link has been sent.</p>
</div>
<a href="/"><button>Back to Login</button></a>
</div></div>
</body></html>
`)
		return
	}

	token := randomToken()
	if token == "" {
		mu.Unlock()
		renderError(w, "Error", "Unable to create reset link. Please try again.", "/forgot-password")
		return
	}
	resetTokens[token] = account.Username
	mu.Unlock()

	resetURL := baseURL() + "/reset-password?token=" + token
	body := fmt.Sprintf(
		"Hello %s,\n\nA password reset was requested for your Caleb's City Mall Bank account.\n\nReset your password here:\n%s\n\nThis link is for your account only. If you did not request this, ignore this email.",
		account.Name, resetURL,
	)

	if err := sendEmail(email, "Reset your Caleb's City Mall Bank password", body); err != nil {
		mu.Lock()
		delete(resetTokens, token)
		mu.Unlock()
		renderError(w, "Email Error", "We could not send the reset email: "+err.Error(), "/forgot-password")
		return
	}

	fmt.Fprintln(w, pageStart("Check Your Email"))
	fmt.Fprintln(w, `
<div class="container"><div class="card">
<div class="success">
<h2>Check Your Email 📧</h2>
<p>If the email belongs to an account, a password-reset link has been sent.</p>
</div>
<a href="/"><button>Back to Login</button></a>
</div></div>
</body></html>
`)
}

func resetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))

	mu.Lock()
	username := resetTokens[token]
	account := findAccount(username)
	valid := token != "" && username != "" && account != nil
	mu.Unlock()

	if !valid {
		renderError(w, "Reset Link Invalid", "This password-reset link is invalid or has already been used.", "/forgot-password")
		return
	}

	captchaID := newCaptcha()

	fmt.Fprintln(w, pageStart("Reset Password"))
	fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>🔑 Reset Password</h1>

<form action="/reset-password" method="POST">

<input type="hidden" name="token" value="%s">

<label>New Password</label>
<div style="display:flex; gap:8px;">
<input id="resetPassword" type="password" name="password" required autocomplete="new-password">
<button type="button" class="show-password" onclick="toggleField('resetPassword', this)">Show</button>
</div>

<label>Confirm New Password</label>
<div style="display:flex; gap:8px;">
<input id="resetConfirm" type="password" name="confirmPassword" required autocomplete="new-password">
<button type="button" class="show-password" onclick="toggleField('resetConfirm', this)">Show</button>
</div>

<div class="info">
<strong>Password requirements:</strong>
<ul>
<li>At least 8 characters</li>
<li>1 uppercase letter</li>
<li>1 lowercase letter</li>
<li>1 number</li>
<li>1 symbol</li>
</ul>
</div>

%s

<button type="submit">Reset Password</button>
</form>

</div>
</div>

<script>
function toggleField(id, button) {
	const field = document.getElementById(id);
	if (field.type === "password") {
		field.type = "text";
		button.textContent = "Hide";
	} else {
		field.type = "password";
		button.textContent = "Show";
	}
}
</script>

</body>
</html>
`,
		template.HTMLEscapeString(token),
		captchaHTML(captchaID),
	)
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if !verifyCaptcha(r.FormValue("captchaID"), r.FormValue("captcha")) {
		renderError(w, "Security Check Failed", "Incorrect or expired CAPTCHA. Please try again.", "/forgot-password")
		return
	}

	if password != confirmPassword {
		renderError(w, "Reset Password", "The passwords do not match.", "/forgot-password")
		return
	}

	if !validPassword(password) {
		renderError(w, "Reset Password", "Password does not meet the requirements.", "/forgot-password")
		return
	}

	mu.Lock()
	username := resetTokens[token]
	account := findAccount(username)

	if token == "" || username == "" || account == nil {
		mu.Unlock()
		renderError(w, "Reset Link Invalid", "This password-reset link is invalid or has already been used.", "/forgot-password")
		return
	}

	account.PasswordHash = hashPassword(password)

	for sessionID, sessionUsername := range sessions {
		if sessionUsername == username {
			delete(sessions, sessionID)
		}
	}

	delete(resetTokens, token)
	persistLocked()
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Password Reset"))
	fmt.Fprintln(w, `
<div class="container"><div class="card">
<div class="success">
<h1>Password Reset Successful! ✅</h1>
<p>Your password has been changed. Any previous login sessions have been signed out.</p>
</div>
<a href="/"><button>Go to Login</button></a>
</div></div>
</body></html>
`)
}

// ----------------------------------------------------
// LOGIN
// ----------------------------------------------------

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		loginPage(w, "")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	if !verifyCaptcha(r.FormValue("captchaID"), r.FormValue("captcha")) {
		loginPage(w, `<div class="error">Incorrect or expired CAPTCHA. Please try again.</div>`)
		return
	}
	mu.Lock()
	var account *Account
	for i := range accounts {
		if strings.EqualFold(accounts[i].Email, email) {
			account = &accounts[i]
			break
		}
	}
	if account == nil || account.PasswordHash != hashPassword(password) {
		mu.Unlock()
		loginPage(w, `<div class="error">Invalid email or password.</div>`)
		return
	}
	if !account.Verified {
		mu.Unlock()
		loginPage(w, `<div class="error">Please verify your email before signing in.</div>`)
		return
	}
	challengeID := randomToken()
	code := randomOTP()
	if challengeID == "" || code == "" {
		mu.Unlock()
		loginPage(w, `<div class="error">Unable to start two-step verification.</div>`)
		return
	}
	loginChallenges[challengeID] = loginChallenge{Username: account.Username, Code: code, Expires: time.Now().Add(10 * time.Minute)}
	name := account.Name
	mu.Unlock()
	if err := sendEmail(email, "Your sign-in verification code", fmt.Sprintf("Hello %s,\n\nYour sign-in verification code is: %s\n\nIt expires in 10 minutes.", name, code)); err != nil {
		mu.Lock()
		delete(loginChallenges, challengeID)
		mu.Unlock()
		loginPage(w, `<div class="error">We could not send your verification code: `+template.HTMLEscapeString(err.Error())+`</div>`)
		return
	}
	fmt.Fprintln(w, pageStart("Two-Step Verification"))
	fmt.Fprintf(w, `<div class="container"><div class="card"><h1>🔐 Two-Step Verification</h1><div class="success">A 6-digit code was sent to <strong>%s</strong>.</div><form action="/verify-login" method="POST"><input type="hidden" name="challenge" value="%s"><label>Verification Code</label><input type="text" name="code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" autocomplete="one-time-code" required><button type="submit">Verify & Sign In</button></form><p><small>The code expires in 10 minutes.</small></p></div></div></body></html>`, template.HTMLEscapeString(email), template.HTMLEscapeString(challengeID))
}
func verifyLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	id := strings.TrimSpace(r.FormValue("challenge"))
	code := strings.TrimSpace(r.FormValue("code"))
	mu.Lock()
	c, ok := loginChallenges[id]
	if !ok || time.Now().After(c.Expires) {
		delete(loginChallenges, id)
		mu.Unlock()
		loginPage(w, `<div class="error">That verification code has expired. Please sign in again.</div>`)
		return
	}
	if c.Attempts >= 5 {
		delete(loginChallenges, id)
		mu.Unlock()
		loginPage(w, `<div class="error">Too many incorrect attempts. Please sign in again.</div>`)
		return
	}
	if code != c.Code {
		c.Attempts++
		loginChallenges[id] = c
		mu.Unlock()
		renderError(w, "Verification Failed", "Incorrect verification code.", "/")
		return
	}
	sessionID := createSession(c.Username)
	delete(loginChallenges, id)
	mu.Unlock()
	if sessionID == "" {
		loginPage(w, `<div class="error">Unable to create your session.</div>`)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionID, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/", MaxAge: 14400})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ----------------------------------------------------
// SEND PAGE
// ----------------------------------------------------

// ----------------------------------------------------

func sendPage(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {

		loginPage(w, `
<div class="error">
Please sign in before sending money.
</div>
`)

		return
	}

	fmt.Fprintln(w, pageStart("Send Money"))

	fmt.Fprintln(w, `

<div class="container">

<div class="card">

<h1>📤 Send Money</h1>

<label>Recipient Account Number</label>

<input
id="accountNumber"
type="text"
placeholder="Start typing account number..."
maxlength="10"
autocomplete="off"
>

<div id="recipient"></div>

<form action="/send-money" method="POST">

<input
id="selectedAccount"
type="hidden"
name="account"
>

<label>Currency to Send</label>

<select name="sendCurrency">

<option value="USD">USD - US Dollar</option>
<option value="EUR">EUR - Euro</option>
<option value="GBP">GBP - British Pound</option>
<option value="JPY">JPY - Japanese Yen</option>
<option value="NGN">NGN - Nigerian Naira</option>
<option value="CAD">CAD - Canadian Dollar</option>
<option value="AUD">AUD - Australian Dollar</option>
<option value="CHF">CHF - Swiss Franc</option>

</select>

<label>Amount</label>

<input
type="number"
name="amount"
step="0.01"
min="0.01"
required
>

<label>Transaction PIN</label>
<input type="password" name="pin" inputmode="numeric" maxlength="4" pattern="[0-9]{4}" required autocomplete="off">

<button type="submit">
Send Money
</button>

</form>

</div>

</div>

<script>

const input =
document.getElementById("accountNumber");

const recipient =
document.getElementById("recipient");

const selected =
document.getElementById("selectedAccount");

input.addEventListener("input", async function() {

	const number = this.value;

	selected.value = "";

	if (number.length === 0) {
		recipient.innerHTML = "";
		return;
	}

	try {

		const response = await fetch(
			"/search?account=" +
			encodeURIComponent(number)
		);

		const data = await response.json();

		if (data.length === 0) {

			recipient.innerHTML =
			"<div class='error'>" +
			"No matching account found." +
			"</div>";

			return;
		}

		let html =
		"<div class='recipient'>" +
		"<strong>Accounts found:</strong>";

		data.forEach(function(account) {

			html +=
			"<div class='suggestion' " +
			"onclick=\"selectAccount('" +
			account.accountNo +
			"')\">" +

			"👤 <strong>" +
			account.name +
			"</strong><br>" +

			"Account: " +
			account.accountNo +
			"<br>" +

			"Currency: " +
			account.currency +

			"</div>";

		});

		html += "</div>";

		recipient.innerHTML = html;

	} catch (error) {

		recipient.innerHTML =
		"<div class='error'>" +
		"Unable to search accounts." +
		"</div>";
	}
});

function selectAccount(number) {

	input.value = number;
	selected.value = number;

	recipient.innerHTML =
	"<div class='success'>" +
	"Recipient selected: " +
	number +
	"</div>";
}

</script>

</body>
</html>

`)
}

// ----------------------------------------------------
// SEARCH ACCOUNTS
// ----------------------------------------------------

func searchAccounts(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {
		http.Error(
			w,
			"Not logged in",
			http.StatusUnauthorized,
		)
		return
	}

	number := r.URL.Query().Get("account")

	results := []SearchResult{}

	mu.Lock()

	for _, account := range accounts {

		if account.Username == username {
			continue
		}

		if strings.HasPrefix(
			account.AccountNo,
			number,
		) {

			results = append(
				results,
				SearchResult{
					Name:      account.Name,
					AccountNo: account.AccountNo,
					Currency:  account.Currency,
				},
			)
		}

		if len(results) >= 10 {
			break
		}
	}

	mu.Unlock()

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(results)
}

// ----------------------------------------------------
// SEND MONEY
// ----------------------------------------------------

func sendMoney(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {

		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)

		return
	}

	accountNumber := strings.TrimSpace(
		r.FormValue("account"),
	)

	sendCurrency := strings.ToUpper(
		r.FormValue("sendCurrency"),
	)

	amount, err := strconv.ParseFloat(
		r.FormValue("amount"),
		64,
	)

	pin := strings.TrimSpace(r.FormValue("pin"))

	if err != nil || amount <= 0 {
		fmt.Fprintln(w, "Invalid amount.")
		return
	}

	mu.Lock()

	sender := findAccount(username)
	receiver := findAccountByNumber(accountNumber)

	if sender == nil || receiver == nil {
		mu.Unlock()

		fmt.Fprintln(w, "Recipient not found.")
		return
	}

	if sender.AccountNo == receiver.AccountNo {
		mu.Unlock()

		fmt.Fprintln(
			w,
			"You cannot send money to yourself.",
		)

		return
	}

	if !validPIN(pin) || sender.PINHash != hashPassword(pin) {
		mu.Unlock()
		fmt.Fprintln(w, pageStart("Transfer Failed"))
		fmt.Fprintln(w, `<div class="container"><div class="card"><div class="error"><h2>Transfer Failed ❌</h2><p>Incorrect transaction PIN.</p></div><a href="/send"><button>Try Again</button></a></div></div></body></html>`)
		return
	}

	senderCurrency := sender.Currency
	receiverCurrency := receiver.Currency

	mu.Unlock()

	senderToSendRate, err := getExchangeRate(
		senderCurrency,
		sendCurrency,
	)

	if err != nil {

		fmt.Fprintln(
			w,
			"Unable to get exchange rate.",
		)

		return
	}

	sendToReceiverRate, err := getExchangeRate(
		sendCurrency,
		receiverCurrency,
	)

	if err != nil {

		fmt.Fprintln(
			w,
			"Unable to get exchange rate.",
		)

		return
	}

	amountFromSender :=
		amount / senderToSendRate

	amountForReceiver :=
		amount * sendToReceiverRate

	mu.Lock()
	defer mu.Unlock()

	sender = findAccount(username)
	receiver = findAccountByNumber(accountNumber)

	if sender == nil || receiver == nil {
		fmt.Fprintln(w, "Account not found.")
		return
	}

	if sender.Balance < amountFromSender {

		fmt.Fprintln(w, pageStart("Transfer Failed"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<div class="error">

<h2>Transfer Failed ❌</h2>

<p>Insufficient balance.</p>

</div>

<a href="/send">
<button>Try Again</button>
</a>

</div>

</div>

</body>
</html>

`)

		return
	}

	sender.Balance -= amountFromSender
	receiver.Balance += amountForReceiver

	now := time.Now().Format(
		"02 Jan 2006, 15:04",
	)

	transactions[username] =
		append(
			transactions[username],
			Transaction{
				Type:     "Sent",
				Amount:   amount,
				Currency: sendCurrency,
				Details: fmt.Sprintf(
					"Sent to %s. Sender charged %.2f %s. Receiver received %.2f %s.",
					receiver.Name,
					amountFromSender,
					senderCurrency,
					amountForReceiver,
					receiverCurrency,
				),
				Date: now,
			},
		)

	transactions[receiver.Username] =
		append(
			transactions[receiver.Username],
			Transaction{
				Type:     "Received",
				Amount:   amountForReceiver,
				Currency: receiverCurrency,
				Details: fmt.Sprintf(
					"Received from %s. Original transfer: %.2f %s.",
					sender.Name,
					amount,
					sendCurrency,
				),
				Date: now,
			},
		)

	persistLocked()

	fmt.Fprintln(w, pageStart("Transfer Successful"))

	fmt.Fprintf(w, `

<div class="container">

<div class="card">

<div class="success">

<h1>Transfer Successful! ✅</h1>

<p>
You sent:
<strong>
%.2f %s
</strong>
</p>

<p>
Your account was charged:
<strong>
%.2f %s
</strong>
</p>

<p>
Recipient received:
<strong>
%.2f %s
</strong>
</p>

<p>
Recipient:
<strong>
%s
</strong>
</p>

</div>

<a href="/transactions">
<button>View Transactions</button>
</a>

<a href="/">
<button>Dashboard</button>
</a>

</div>

</div>

</body>
</html>

`,
		amount,
		sendCurrency,
		amountFromSender,
		senderCurrency,
		amountForReceiver,
		receiverCurrency,
		template.HTMLEscapeString(receiver.Name),
	)
}

// ----------------------------------------------------
// WITHDRAW PAGE
// ----------------------------------------------------

func withdrawPage(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {

		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)

		return
	}

	fmt.Fprintln(w, pageStart("Withdraw"))

	fmt.Fprintln(w, `

<div class="container">

<div class="card">

<h1>💵 Withdraw Money</h1>

<form action="/withdraw-money" method="POST">

<label>Amount</label>

<input
type="number"
name="amount"
step="0.01"
min="0.01"
required
>

<button type="submit">
Withdraw
</button>

</form>

</div>

</div>

</body>
</html>

`)
}

// ----------------------------------------------------
// WITHDRAW
// ----------------------------------------------------

func withdraw(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {

		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)

		return
	}

	amount, err := strconv.ParseFloat(
		r.FormValue("amount"),
		64,
	)

	if err != nil || amount <= 0 {

		fmt.Fprintln(
			w,
			"Invalid amount.",
		)

		return
	}

	mu.Lock()
	defer mu.Unlock()

	account := findAccount(username)

	if account == nil {

		fmt.Fprintln(
			w,
			"Account not found.",
		)

		return
	}

	if account.Balance < amount {

		fmt.Fprintln(w, pageStart("Withdrawal Failed"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<div class="error">

<h2>Withdrawal Failed ❌</h2>

<p>Insufficient balance.</p>

</div>

<a href="/withdraw">
<button>Try Again</button>
</a>

</div>

</div>

</body>
</html>

`)

		return
	}

	account.Balance -= amount

	now := time.Now().Format(
		"02 Jan 2006, 15:04",
	)

	transactions[username] =
		append(
			transactions[username],
			Transaction{
				Type:     "Withdrawal",
				Amount:   amount,
				Currency: account.Currency,
				Details:  "Cash withdrawal",
				Date:     now,
			},
		)

	persistLocked()

	fmt.Fprintln(w, pageStart("Withdrawal Successful"))

	fmt.Fprintf(w, `

<div class="container">

<div class="card">

<div class="success">

<h1>Withdrawal Successful! ✅</h1>

<p>
You withdrew:
<strong>
%.2f %s
</strong>
</p>

</div>

<a href="/transactions">
<button>View Transactions</button>
</a>

</div>

</div>

</body>
</html>

`,
		amount,
		account.Currency,
	)
}

// ----------------------------------------------------
// TRANSACTIONS
// ----------------------------------------------------

func transactionPage(w http.ResponseWriter, r *http.Request) {

	username := getLoggedInUser(r)

	if username == "" {

		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)

		return
	}

	mu.Lock()

	userTransactions :=
		append(
			[]Transaction(nil),
			transactions[username]...,
		)

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Transactions"))

	fmt.Fprintln(w, `

<div class="container">

<div class="card">

<h1>📜 Transactions</h1>

`)

	if len(userTransactions) == 0 {

		fmt.Fprintln(w, `
<p>No transactions yet.</p>
`)

	} else {

		for i := len(userTransactions) - 1; i >= 0; i-- {

			t := userTransactions[i]

			class := "sent"
			icon := "📤"

			if t.Type == "Received" {
				class = "received"
				icon = "📥"
			}

			if t.Type == "Withdrawal" {
				class = "withdrawal"
				icon = "💵"
			}

			fmt.Fprintf(w, `

<div class="transaction %s">

<h3>
%s %s
</h3>

<p>%s</p>

<strong>
%.2f %s
</strong>

<p>
<small>%s</small>
</p>

</div>

`,
				class,
				icon,
				t.Type,
				template.HTMLEscapeString(t.Details),
				t.Amount,
				t.Currency,
				t.Date,
			)
		}
	}

	fmt.Fprintln(w, `

</div>

</div>

</body>
</html>
`)
}

// ----------------------------------------------------
// PROFILE
// ----------------------------------------------------

func profilePage(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		loginPage(w, `<div class="error">Please sign in first.</div>`)
		return
	}

	mu.Lock()
	account := findAccount(username)
	if account == nil {
		mu.Unlock()
		fmt.Fprintln(w, "Account not found.")
		return
	}

	name := account.Name
	user := account.Username
	email := account.Email
	number := account.AccountNo
	currency := account.Currency
	balance := account.Balance
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Profile"))

	fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>👤 My Profile</h1>

<p><strong>Name:</strong> %s</p>
<p><strong>Username:</strong> %s</p>
<p><strong>Email:</strong> %s</p>

<p><strong>Account Number:</strong></p>
<div class="account-number">%s</div>

<p><strong>Currency:</strong> %s</p>
<p><strong>Balance:</strong> %.2f %s</p>

<hr>

<p><strong>Password:</strong> ••••••••</p>
<p>Your password is never stored in readable form.</p>

<a href="/change-password"><button>Change Password</button></a>
<a href="/change-currency"><button>Change Currency</button></a>

</div>
</div>

</body>
</html>
`,
		template.HTMLEscapeString(name),
		template.HTMLEscapeString(user),
		template.HTMLEscapeString(email),
		template.HTMLEscapeString(number),
		template.HTMLEscapeString(currency),
		balance,
		template.HTMLEscapeString(currency),
	)
}

// ----------------------------------------------------
// CHANGE PASSWORD
// ----------------------------------------------------

// ----------------------------------------------------

func changePasswordPage(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		loginPage(w, `<div class="error">Please sign in first.</div>`)
		return
	}

	captchaID := newCaptcha()

	fmt.Fprintln(w, pageStart("Change Password"))
	fmt.Fprintf(w, `
<div class="container">
<div class="card">

<h1>🔑 Change Password</h1>

<form action="/change-password" method="POST">

<label>Current Password</label>
<div style="display:flex; gap:8px;">
<input id="currentPassword" type="password" name="currentPassword" required>
<button type="button" class="show-password" onclick="toggleField('currentPassword', this)">Show</button>
</div>

<label>New Password</label>
<div style="display:flex; gap:8px;">
<input id="newPassword" type="password" name="newPassword" required>
<button type="button" class="show-password" onclick="toggleField('newPassword', this)">Show</button>
</div>

<label>Confirm New Password</label>
<div style="display:flex; gap:8px;">
<input id="confirmPassword" type="password" name="confirmPassword" required>
<button type="button" class="show-password" onclick="toggleField('confirmPassword', this)">Show</button>
</div>

<div class="info">
<strong>Password requirements:</strong>
<ul>
<li>At least 8 characters</li>
<li>1 uppercase letter</li>
<li>1 lowercase letter</li>
<li>1 number</li>
<li>1 symbol</li>
</ul>
</div>

%s

<button type="submit">Change Password</button>
</form>

</div>
</div>

<script>
function toggleField(id, button) {
	const field = document.getElementById(id);
	if (field.type === "password") {
		field.type = "text";
		button.textContent = "Hide";
	} else {
		field.type = "password";
		button.textContent = "Show";
	}
}
</script>

</body>
</html>
`, captchaHTML(captchaID))
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		loginPage(w, `<div class="error">Please sign in first.</div>`)
		return
	}

	if !verifyCaptcha(r.FormValue("captchaID"), r.FormValue("captcha")) {
		renderError(w, "Security Check Failed", "Incorrect or expired CAPTCHA. Please try again.", "/change-password")
		return
	}

	current := r.FormValue("currentPassword")
	newPassword := r.FormValue("newPassword")
	confirm := r.FormValue("confirmPassword")

	if newPassword != confirm {
		renderError(w, "Change Password", "The new passwords do not match.", "/change-password")
		return
	}

	if !validPassword(newPassword) {
		renderError(w, "Change Password", "Password does not meet the requirements.", "/change-password")
		return
	}

	mu.Lock()
	account := findAccount(username)
	if account == nil || account.PasswordHash != hashPassword(current) {
		mu.Unlock()
		renderError(w, "Change Password", "Your current password is incorrect.", "/change-password")
		return
	}

	account.PasswordHash = hashPassword(newPassword)
	persistLocked()
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Password Changed"))
	fmt.Fprintln(w, `
<div class="container"><div class="card">
<div class="success">
<h1>Password Changed! ✅</h1>
<p>Your password has been updated successfully.</p>
</div>
<a href="/"><button>Back to Dashboard</button></a>
</div></div>
</body></html>
`)
}

// ----------------------------------------------------
// CHANGE CURRENCY
// ----------------------------------------------------

func changeCurrencyPage(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		loginPage(w, `<div class="error">Please sign in first.</div>`)
		return
	}

	mu.Lock()
	account := findAccount(username)
	if account == nil {
		mu.Unlock()
		loginPage(w, `<div class="error">Account not found.</div>`)
		return
	}
	currentCurrency := account.Currency
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Change Currency"))
	fmt.Fprintf(w, `
<div class="container"><div class="card">

<h1>💱 Change Account Currency</h1>
<p>Current currency: <strong>%s</strong></p>
<p>Your balance will be converted using the current exchange rate.</p>

<form action="/change-currency" method="POST">

<label>New Currency</label>
<select name="currency">
<option value="USD">USD - US Dollar</option>
<option value="EUR">EUR - Euro</option>
<option value="GBP">GBP - British Pound</option>
<option value="JPY">JPY - Japanese Yen</option>
<option value="NGN">NGN - Nigerian Naira</option>
<option value="CAD">CAD - Canadian Dollar</option>
<option value="AUD">AUD - Australian Dollar</option>
<option value="CHF">CHF - Swiss Franc</option>
</select>

<button type="submit">Change Currency</button>
</form>

</div></div>
</body></html>
`, template.HTMLEscapeString(currentCurrency))
}

func changeCurrency(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)
	if username == "" {
		loginPage(w, `<div class="error">Please sign in first.</div>`)
		return
	}

	newCurrency := strings.ToUpper(strings.TrimSpace(r.FormValue("currency")))

	valid := false
	for _, c := range currencies {
		if c == newCurrency {
			valid = true
			break
		}
	}
	if !valid {
		renderError(w, "Currency Error", "Invalid currency.", "/change-currency")
		return
	}

	mu.Lock()
	account := findAccount(username)
	if account == nil {
		mu.Unlock()
		renderError(w, "Error", "Account not found.", "/change-currency")
		return
	}
	oldCurrency := account.Currency
	oldBalance := account.Balance
	mu.Unlock()

	if oldCurrency == newCurrency {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	rate, err := getExchangeRate(oldCurrency, newCurrency)
	if err != nil {
		renderError(w, "Currency Error", "Unable to get the exchange rate. Please try again later.", "/change-currency")
		return
	}

	newBalance := oldBalance * rate

	mu.Lock()
	account = findAccount(username)
	if account == nil {
		mu.Unlock()
		renderError(w, "Error", "Account not found.", "/change-currency")
		return
	}
	account.Balance = newBalance
	account.Currency = newCurrency

	transactions[username] = append(transactions[username], Transaction{
		Type:     "Currency Change",
		Amount:   newBalance,
		Currency: newCurrency,
		Details:  fmt.Sprintf("Account currency changed from %s to %s. Balance converted using the current exchange rate.", oldCurrency, newCurrency),
		Date:     time.Now().Format("02 Jan 2006, 15:04"),
	})

	persistLocked()
	mu.Unlock()

	fmt.Fprintln(w, pageStart("Currency Changed"))
	fmt.Fprintf(w, `
<div class="container"><div class="card">
<div class="success">
<h1>Currency Changed! ✅</h1>
<p>Your account currency is now <strong>%s</strong>.</p>
<p>New balance: <strong>%.2f %s</strong></p>
</div>
<a href="/profile"><button>Back to Profile</button></a>
</div></div>
</body></html>
`, template.HTMLEscapeString(newCurrency), newBalance, template.HTMLEscapeString(newCurrency))
}

// ----------------------------------------------------
// LOGOUT
// ----------------------------------------------------

func logout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")

	if err == nil {

		mu.Lock()

		delete(
			sessions,
			cookie.Value,
		)

		mu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})
	}

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)
}

// ----------------------------------------------------
// TEST ACCOUNT NAMES
// ----------------------------------------------------

var firstNames = []string{
	"James", "John", "Robert", "Michael", "William",
	"David", "Richard", "Joseph", "Thomas", "Charles",
	"Christopher", "Daniel", "Matthew", "Anthony", "Mark",
	"Donald", "Steven", "Paul", "Andrew", "Joshua",
	"Kenneth", "Kevin", "Brian", "George", "Edward",
	"Ronald", "Timothy", "Jason", "Jeffrey", "Ryan",
	"Jacob", "Gary", "Nicholas", "Eric", "Jonathan",
	"Stephen", "Larry", "Justin", "Scott", "Brandon",
	"Benjamin", "Samuel", "Gregory", "Alexander", "Patrick",
	"Frank", "Raymond", "Jack", "Dennis", "Jerry",
}

var lastNames = []string{
	"Smith", "Johnson", "Williams", "Brown", "Jones",
	"Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
	"Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
	"Thomas", "Taylor", "Moore", "Jackson", "Martin",
	"Lee", "Perez", "Thompson", "White", "Harris",
	"Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
	"Walker", "Young", "Allen", "King", "Wright",
	"Scott", "Torres", "Nguyen", "Hill", "Flores",
	"Green", "Adams", "Nelson", "Baker", "Hall",
	"Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
}

// ----------------------------------------------------
// TEST ACCOUNTS
// ----------------------------------------------------

func createTestAccounts() error {

	rates := make(map[string]float64)

	fmt.Println("Getting exchange rates...")

	for _, currency := range currencies {

		rate, err := getExchangeRate(
			"USD",
			currency,
		)

		if err != nil {
			return fmt.Errorf(
				"could not get USD to %s rate: %v",
				currency,
				err,
			)
		}

		rates[currency] = rate
	}

	fmt.Println("Creating test accounts...")

	for i := 0; i < 1000; i++ {

		first :=
			firstNames[i%len(firstNames)]

		last :=
			lastNames[(i/len(firstNames))%
				len(lastNames)]

		name :=
			fmt.Sprintf(
				"%s %s",
				first,
				last,
			)

		username :=
			fmt.Sprintf(
				"customer%04d",
				i+1,
			)

		password :=
			fmt.Sprintf(
				"BankUser%04d!",
				i+1,
			)

		currency :=
			currencies[i%len(currencies)]

		accountNumber :=
			generateAccountNumber()

		balance :=
			1000 * rates[currency]

		accounts =
			append(
				accounts,
				Account{
					Name:         name,
					Username:     username,
					Email:        username + "@example.com",
					PasswordHash: hashPassword(password),
					Verified:     true,
					AccountNo:    accountNumber,
					Currency:     currency,
					Balance:      balance,
				},
			)
	}

	return nil
}

// ----------------------------------------------------
// MAIN
// ----------------------------------------------------

func main() {

	sessions = make(map[string]string)

	fmt.Println("==============================================")
	fmt.Println("       CALEB'S CITY MALL BANK")
	fmt.Println("==============================================")

	// Diagnostic: confirms whether the running process can actually
	// see RESEND_API_KEY and EMAIL_FROM. Check your Render logs after
	// deploying — if either says "NOT SET", the env vars aren't reaching
	// this process (wrong service, needs redeploy, name typo, etc.),
	// even if they look correct in the Render dashboard.
	if os.Getenv("RESEND_API_KEY") != "" {
		fmt.Println("RESEND_API_KEY: set (", len(os.Getenv("RESEND_API_KEY")), "chars )")
	} else {
		fmt.Println("RESEND_API_KEY: NOT SET")
	}
	if os.Getenv("EMAIL_FROM") != "" {
		fmt.Println("EMAIL_FROM:", os.Getenv("EMAIL_FROM"))
	} else {
		fmt.Println("EMAIL_FROM: NOT SET")
	}
	fmt.Println("==============================================")

	// Try to load existing accounts/transactions from disk
	// first (data.json). This is what makes the app survive
	// restarts instead of wiping every account and generating
	// a fresh set of 1,000 test accounts every single time.
	if loadState() {

		fmt.Println("")
		fmt.Printf(
			"Loaded existing data from %s (%d accounts).\n",
			dataFile,
			len(accounts),
		)

	} else {

		accounts = []Account{}
		transactions = make(map[string][]Transaction)

		err := createTestAccounts()

		if err != nil {
			fmt.Println("")
			fmt.Println("ERROR:")
			fmt.Println(err)
			fmt.Println("")
			fmt.Println("Check your internet connection.")
			return
		}

		mu.Lock()
		persistLocked()
		mu.Unlock()

		fmt.Println("")
		fmt.Println("1,000 test accounts created.")
		fmt.Println("")
		fmt.Println("TEST LOGIN")
		fmt.Println("------------------------------")
		fmt.Println("Email: customer0001@example.com")
		fmt.Println("Password: BankUser0001!")
		fmt.Println("------------------------------")
	}

	http.HandleFunc("/", home)

	http.HandleFunc("/register", registerPage)
	http.HandleFunc("/login", login)
	http.HandleFunc("/verify-login", verifyLogin)
	http.HandleFunc("/captcha-image", captchaImage)
	http.HandleFunc("/verify-email", verifyEmail)
	http.HandleFunc("/forgot-password", forgotPasswordPage)
	http.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			resetPasswordPage(w, r)
		} else {
			resetPassword(w, r)
		}
	})

	http.HandleFunc("/change-password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			changePasswordPage(w, r)
		} else {
			changePassword(w, r)
		}
	})

	http.HandleFunc("/change-currency", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			changeCurrencyPage(w, r)
		} else {
			changeCurrency(w, r)
		}
	})

	http.HandleFunc("/send", sendPage)
	http.HandleFunc("/send-money", sendMoney)
	http.HandleFunc("/search", searchAccounts)

	http.HandleFunc("/withdraw", withdrawPage)
	http.HandleFunc("/withdraw-money", withdraw)

	http.HandleFunc("/transactions", transactionPage)
	http.HandleFunc("/profile", profilePage)
	http.HandleFunc("/logout", logout)

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	fmt.Println("")
	fmt.Println("Server running on port:", port)
	fmt.Println("")

	err := http.ListenAndServe(":"+port, nil)

	if err != nil {
		fmt.Println("Server error:", err)
	}
}
