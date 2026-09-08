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
	PasswordHash string
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
	mu           sync.Mutex
)

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

	accounts = state.Accounts

	if state.Transactions != nil {
		transactions = state.Transactions
	} else {
		transactions = make(map[string][]Transaction)
	}

	return true
}

// ----------------------------------------------------
// PASSWORD
// ----------------------------------------------------

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}

func validPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var upper, lower, number, symbol bool

	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			number = true
		default:
			symbol = true
		}
	}

	return upper && lower && number && symbol
}

// ----------------------------------------------------
// ACCOUNT NUMBERS
// ----------------------------------------------------

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

	fmt.Fprintln(w, pageStart("Login"))

	fmt.Fprintf(w, `

<div class="container">

<div class="card">

<h1>Welcome Back 👋</h1>

<p>Sign in to Caleb's City Mall Bank.</p>

%s

<form action="/login" method="POST">

<label>Username</label>

<input
type="text"
name="username"
required
>

<label>Password</label>

<input
type="password"
name="password"
required
>

<button type="submit">
Sign In
</button>

</form>

<p>
<a href="/forgot-password">Forgot your password?</a>
</p>

<p>
Don't have an account?
<a href="/register">Create an account</a>
</p>

</div>

</div>

</body>
</html>

`, message)
}

// ----------------------------------------------------
// REGISTER
// ----------------------------------------------------

func registerPage(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {

		fmt.Fprintln(w, pageStart("Register"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<h1>🏦 Create Account</h1>

<form action="/register" method="POST">

<label>Full Name</label>

<input
type="text"
name="name"
required
>

<label>Username</label>

<input
type="text"
name="username"
required
>

<label>Password</label>

<input
type="password"
name="password"
required
>

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

<button type="submit">
Create Account
</button>

</form>

<p>
Already have an account?
<a href="/">Sign in</a>
</p>

</div>

</div>

</body>
</html>

`)

		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	currency := strings.ToUpper(r.FormValue("currency"))

	if name == "" || username == "" || password == "" {
		fmt.Fprintln(w, "Please complete all fields.")
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
		fmt.Fprintln(w, "Invalid currency.")
		return
	}

	if !validPassword(password) {

		fmt.Fprintln(w, pageStart("Password Error"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<div class="error">

<strong>Password does not meet the requirements.</strong>

<ul>
<li>At least 8 characters</li>
<li>1 uppercase letter</li>
<li>1 lowercase letter</li>
<li>1 number</li>
<li>1 symbol</li>
</ul>

</div>

<a href="/register">
<button>Try Again</button>
</a>

</div>

</div>

</body>
</html>

`)

		return
	}

	mu.Lock()

	if findAccount(username) != nil {
		mu.Unlock()

		fmt.Fprintln(w, pageStart("Error"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<div class="error">
That username already exists.
</div>

<a href="/register">
<button>Try Again</button>
</a>

</div>

</div>

</body>
</html>

`)

		return
	}

	accountNumber := generateAccountNumber()

	mu.Unlock()

	rate, err := getExchangeRate("USD", currency)

	if err != nil {

		fmt.Fprintln(w, pageStart("Error"))

		fmt.Fprintln(w, `

<div class="container">

<div class="card">

<div class="error">
Unable to get the exchange rate.
Please try again later.
</div>

<a href="/register">
<button>Try Again</button>
</a>

</div>

</div>

</body>
</html>

`)

		return
	}

	startingBalance := 1000 * rate

	mu.Lock()

	accounts = append(accounts, Account{
		Name:         name,
		Username:     username,
		PasswordHash: hashPassword(password),
		AccountNo:    accountNumber,
		Currency:     currency,
		Balance:      startingBalance,
	})

	persistLocked()

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Account Created"))

	fmt.Fprintf(w, `

<div class="container">

<div class="card">

<div class="success">

<h1>Account Created! 🎉</h1>

</div>

<h2>Welcome, %s!</h2>

<p>Your account number:</p>

<div class="account-number">
%s
</div>

<p>
Starting balance:
<strong>%.2f %s</strong>
</p>

<p>
This is approximately equal to $1,000 USD.
</p>

<a href="/">
<button>Go to Login</button>
</a>

</div>

</div>

</body>
</html>

`,
		template.HTMLEscapeString(name),
		accountNumber,
		startingBalance,
		currency,
	)
}

// ----------------------------------------------------
// FORGOT PASSWORD / PASSWORD RESET
// ----------------------------------------------------
//
// Demo recovery flow:
// 1. User enters username + account number.
// 2. If both match, the user can choose a new password.
// 3. All existing sessions for that username are invalidated.
//
// For a real banking system, recovery should use a verified
// email/phone plus a one-time, expiring reset token.
// ----------------------------------------------------

func forgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintln(w, pageStart("Forgot Password"))

		fmt.Fprintln(w, `
<div class="container">

<div class="card">

<h1>🔐 Forgot Password</h1>

<p>Enter your username and account number to verify your account.</p>

<form action="/forgot-password" method="POST">

<label>Username</label>

<input
type="text"
name="username"
required
autocomplete="username"
>

<label>Account Number</label>

<input
type="text"
name="account"
required
maxlength="10"
inputmode="numeric"
>

<button type="submit">
Continue
</button>

</form>

<p>
<a href="/">Back to login</a>
</p>

</div>

</div>

</body>
</html>
`)

		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	accountNumber := strings.TrimSpace(r.FormValue("account"))

	if username == "" || accountNumber == "" {
		fmt.Fprintln(w, pageStart("Forgot Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">
Please enter both your username and account number.
</div>

<a href="/forgot-password">
<button>Try Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	mu.Lock()
	account := findAccount(username)

	matches := account != nil && account.AccountNo == accountNumber

	mu.Unlock()

	if !matches {
		fmt.Fprintln(w, pageStart("Forgot Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">
The username and account number could not be verified.
</div>

<a href="/forgot-password">
<button>Try Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	// The account was verified. Show the password-reset form.
	fmt.Fprintln(w, pageStart("Reset Password"))

	fmt.Fprintln(w, `
<div class="container">

<div class="card">

<h1>🔑 Reset Password</h1>

<div class="success">
Account verified. Choose a new password.
</div>

<form action="/reset-password" method="POST">

<input
type="hidden"
name="username"
value="` + template.HTMLEscapeString(username) + `"
>

<input
type="hidden"
name="account"
value="` + template.HTMLEscapeString(accountNumber) + `"
>

<label>New Password</label>

<input
type="password"
name="password"
required
autocomplete="new-password"
>

<label>Confirm New Password</label>

<input
type="password"
name="confirmPassword"
required
autocomplete="new-password"
>

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

<button type="submit">
Reset Password
</button>

</form>

</div>

</div>

</body>
</html>
`)
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	accountNumber := strings.TrimSpace(r.FormValue("account"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	if username == "" || accountNumber == "" {
		fmt.Fprintln(w, pageStart("Reset Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">
Invalid password reset request.
</div>

<a href="/forgot-password">
<button>Start Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	if password != confirmPassword {
		fmt.Fprintln(w, pageStart("Reset Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">
The passwords do not match.
</div>

<a href="/forgot-password">
<button>Try Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	if !validPassword(password) {
		fmt.Fprintln(w, pageStart("Reset Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">

<strong>Password does not meet the requirements.</strong>

<ul>
<li>At least 8 characters</li>
<li>1 uppercase letter</li>
<li>1 lowercase letter</li>
<li>1 number</li>
<li>1 symbol</li>
</ul>

</div>

<a href="/forgot-password">
<button>Try Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	mu.Lock()

	account := findAccount(username)

	if account == nil || account.AccountNo != accountNumber {
		mu.Unlock()

		fmt.Fprintln(w, pageStart("Reset Password"))

		fmt.Fprintln(w, `
<div class="container">
<div class="card">

<div class="error">
The account could not be verified. Please start again.
</div>

<a href="/forgot-password">
<button>Start Again</button>
</a>

</div>
</div>

</body>
</html>
`)

		return
	}

	account.PasswordHash = hashPassword(password)

	// Invalidate all existing login sessions for this account.
	for sessionID, sessionUsername := range sessions {
		if sessionUsername == username {
			delete(sessions, sessionID)
		}
	}

	persistLocked()

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Password Reset"))

	fmt.Fprintln(w, `
<div class="container">

<div class="card">

<div class="success">

<h1>Password Reset Successful! ✅</h1>

<p>Your password has been changed successfully.</p>

<p>For your security, any previous login sessions have been signed out.</p>

</div>

<a href="/">
<button>Go to Login</button>
</a>

</div>

</div>

</body>
</html>
`)
}

// ----------------------------------------------------
// LOGIN
// ----------------------------------------------------

func login(w http.ResponseWriter, r *http.Request) {

	username := strings.TrimSpace(
		r.FormValue("username"),
	)

	password := r.FormValue("password")

	mu.Lock()

	account := findAccount(username)

	if account == nil ||
		account.PasswordHash != hashPassword(password) {

		mu.Unlock()

		loginPage(w, `
<div class="error">
Invalid username or password.
</div>
`)

		return
	}

	sessionID := createSession(username)

	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)
}

// ----------------------------------------------------
// SEND PAGE
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

		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)

		return
	}

	mu.Lock()

	account := findAccount(username)

	if account == nil {

		mu.Unlock()

		fmt.Fprintln(
			w,
			"Account not found.",
		)

		return
	}

	name := account.Name
	user := account.Username
	number := account.AccountNo
	currency := account.Currency
	balance := account.Balance

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Profile"))

	fmt.Fprintf(w, `

<div class="container">

<div class="card">

<h1>👤 My Profile</h1>

<p>
<strong>Name:</strong> %s
</p>

<p>
<strong>Username:</strong> %s
</p>

<p>
<strong>Account Number:</strong>
</p>

<div class="account-number">
%s
</div>

<p>
<strong>Currency:</strong> %s
</p>

<p>
<strong>Balance:</strong>
%.2f %s
</p>

<hr>

<p>
<strong>Password:</strong>
••••••••
</p>

<p>
Your password is securely stored and cannot be displayed.
</p>

</div>

</div>

</body>
</html>

`,
		template.HTMLEscapeString(name),
		template.HTMLEscapeString(user),
		template.HTMLEscapeString(number),
		template.HTMLEscapeString(currency),
		balance,
		template.HTMLEscapeString(currency),
	)
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
			lastNames[
				(i/len(firstNames))%
					len(lastNames),
			]

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
			currencies[
				i%len(currencies),
			]

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
					PasswordHash: hashPassword(password),
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
		fmt.Println("Username: customer0001")
		fmt.Println("Password: BankUser0001!")
		fmt.Println("------------------------------")
	}

	http.HandleFunc("/", home)

	http.HandleFunc("/register", registerPage)
	http.HandleFunc("/login", login)
	http.HandleFunc("/forgot-password", forgotPasswordPage)
	http.HandleFunc("/reset-password", resetPassword)

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