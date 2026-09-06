package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
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
	Balance      float64
}

type Transaction struct {
	Type    string
	Amount  float64
	Details string
	Date    string
}

type SearchResult struct {
	Name      string `json:"name"`
	AccountNo string `json:"accountNo"`
}

var (
	accounts     []Account
	transactions = make(map[string][]Transaction)
	sessions     = make(map[string]string)
	mu           sync.Mutex
)

// ---------- PASSWORD ----------

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// ---------- ACCOUNT NUMBER ----------

func generateAccountNumber() string {
	for {
		b := make([]byte, 4)

		_, err := rand.Read(b)
		if err != nil {
			continue
		}

		number := 1000000000 + int(
			uint32(b[0])<<24|
				uint32(b[1])<<16|
				uint32(b[2])<<8|
				uint32(b[3]),
		)%900000000

		accountNumber := strconv.Itoa(number)

		exists := false

		for _, account := range accounts {
			if account.AccountNo == accountNumber {
				exists = true
				break
			}
		}

		if !exists {
			return accountNumber
		}
	}
}

// ---------- SESSIONS ----------

func createSession(username string) string {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
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

// ---------- FIND ACCOUNTS ----------

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

// ---------- HEADER ----------

func pageStart(title string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
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
	background: linear-gradient(135deg, #4b2aad, #1769e0);
	color: white;
	padding: 18px 7%%;
	display: flex;
	justify-content: space-between;
	align-items: center;
	flex-wrap: wrap;
}

.logo {
	font-size: 22px;
	font-weight: bold;
}

.navbar a {
	color: white;
	text-decoration: none;
	margin-left: 18px;
}

.container {
	max-width: 1000px;
	margin: 35px auto;
	padding: 20px;
}

.card {
	background: white;
	padding: 25px;
	margin-bottom: 25px;
	border-radius: 15px;
	box-shadow: 0 5px 20px rgba(0,0,0,0.08);
}

.hero {
	background: linear-gradient(135deg, #4b2aad, #1769e0);
	color: white;
	padding: 40px;
	border-radius: 18px;
	margin-bottom: 25px;
}

.balance {
	font-size: 38px;
	font-weight: bold;
	margin-top: 10px;
}

.account-number {
	background: #eef2ff;
	padding: 15px;
	border-radius: 10px;
	font-size: 20px;
	font-weight: bold;
	letter-spacing: 2px;
}

input {
	width: 100%%;
	padding: 13px;
	margin: 8px 0 15px;
	border: 1px solid #ccd2e0;
	border-radius: 8px;
	font-size: 15px;
}

button {
	background: linear-gradient(135deg, #4b2aad, #1769e0);
	color: white;
	border: none;
	padding: 13px 20px;
	border-radius: 8px;
	cursor: pointer;
	font-size: 15px;
}

button:hover {
	opacity: 0.9;
}

.grid {
	display: grid;
	grid-template-columns: repeat(2, 1fr);
	gap: 20px;
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
}
</style>

</head>

<body>

<div class="navbar">

<div class="logo">
🏦 Caleb's City Mall Bank
</div>

<div>
<a href="/">Dashboard</a>
<a href="/send">Send</a>
<a href="/withdraw">Withdraw</a>
<a href="/transactions">Transactions</a>
<a href="/profile">Profile</a>
<a href="/logout">Logout</a>
</div>

</div>
`, title)
}

// ---------- LOGIN PAGE ----------

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
<input type="text" name="username" required>

<label>Password</label>
<input type="password" name="password" required>

<button type="submit">Sign In</button>

</form>

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

// ---------- DASHBOARD ----------

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
	accountNo := account.AccountNo
	balance := account.Balance

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Dashboard"))

	fmt.Fprintf(w, `
<div class="container">

<div class="hero">

<h1>Welcome, %s! 👋</h1>

<p>Caleb's City Mall Bank</p>

<p>Available Balance</p>

<div class="balance">
$%.2f
</div>

</div>

<div class="grid">

<div class="card">

<h2>💳 Your Account</h2>

<p>Account Number:</p>

<div class="account-number">
%s
</div>

<p>
Use this number when another customer wants to send you money.
</p>

</div>

<div class="card">

<h2>📤 Send Money</h2>

<p>Transfer money to another customer.</p>

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

<p>View your banking activity.</p>

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
		template.HTMLEscapeString(accountNo),
	)
}

// ---------- REGISTER ----------

func registerPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintln(w, pageStart("Register"))

		fmt.Fprintln(w, `
<div class="container">

<div class="card">

<h1>🏦 Create Your Account</h1>

<p>Join Caleb's City Mall Bank.</p>

<form action="/register" method="POST">

<label>Full Name</label>
<input type="text" name="name" placeholder="Enter your name" required>

<label>Username</label>
<input type="text" name="username" placeholder="Choose a username" required>

<label>Password</label>
<input type="password" name="password" placeholder="Create a password" required>

<button type="submit">Create Account</button>

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

	if name == "" || username == "" || password == "" {
		fmt.Fprintln(w, "Please complete all fields.")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if findAccount(username) != nil {
		fmt.Fprintln(w, `
<h1>Registration Failed</h1>
<p>That username already exists.</p>
<a href="/register">Try Again</a>
`)
		return
	}

	accountNumber := generateAccountNumber()

	account := Account{
		Name:         name,
		Username:     username,
		PasswordHash: hashPassword(password),
		AccountNo:    accountNumber,
		Balance:      1000,
	}

	accounts = append(accounts, account)

	fmt.Fprintln(w, pageStart("Account Created"))

	fmt.Fprintf(w, `
<div class="container">

<div class="card">

<div class="success">
<h1>Account Created Successfully! 🎉</h1>
</div>

<h2>Welcome, %s!</h2>

<p>Your unique account number is:</p>

<div class="account-number">
%s
</div>

<p>
Starting Balance:
<strong>$1,000.00</strong>
</p>

<p>
Give your account number to other customers so they can send you money.
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
		template.HTMLEscapeString(accountNumber),
	)
}

// ---------- LOGIN ----------

func login(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	mu.Lock()

	account := findAccount(username)

	if account == nil || account.PasswordHash != hashPassword(password) {
		mu.Unlock()

		loginPage(w, `
<div class="error">
Incorrect username or password.
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
		Path:     "/",
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------- SEND PAGE ----------

func sendPage(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)

	if username == "" {
		loginPage(w, `
<div class="error">
Please sign in first.
</div>
`)
		return
	}

	fmt.Fprintln(w, pageStart("Send Money"))

	fmt.Fprintln(w, `
<div class="container">

<div class="card">

<h1>📤 Send Money</h1>

<p>Enter an account number to find the recipient.</p>

<form action="/send-money" method="POST">

<label>Recipient Account Number</label>

<input
id="accountNumber"
type="text"
name="account"
placeholder="Start typing account number..."
maxlength="10"
autocomplete="off"
required
>

<div id="recipient"></div>

<label>Amount</label>

<input
type="number"
name="amount"
step="0.01"
min="0.01"
placeholder="Enter amount"
required
>

<button type="submit">
Send Money
</button>

</form>

</div>
</div>

<script>

const input = document.getElementById("accountNumber");
const recipient = document.getElementById("recipient");

input.addEventListener("input", async function() {

	const number = this.value;

	if (number.length === 0) {
		recipient.innerHTML = "";
		return;
	}

	const response = await fetch(
		"/search?account=" + encodeURIComponent(number)
	);

	const data = await response.json();

	if (data.length === 0) {

		recipient.innerHTML =
		"<div class='error'>No matching account found.</div>";

		return;
	}

	let html =
	"<div class='recipient'>" +
	"<strong>Matching Accounts</strong>";

	data.forEach(function(account) {

		html +=
		"<div class='suggestion' " +
		"onclick=\"selectAccount('" +
		account.accountNo +
		"')\">" +

		"👤 <strong>" +
		account.name +
		"</strong>" +

		"<br>" +

		"<small>Account: " +
		account.accountNo +
		"</small>" +

		"</div>";

	});

	html += "</div>";

	recipient.innerHTML = html;
});

function selectAccount(number) {

	input.value = number;

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

// ---------- SEARCH ----------

func searchAccounts(w http.ResponseWriter, r *http.Request) {
	username := getLoggedInUser(r)

	if username == "" {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	number := r.URL.Query().Get("account")

	results := []SearchResult{}

	mu.Lock()

	for _, account := range accounts {

		if account.Username == username {
			continue
		}

		if strings.HasPrefix(account.AccountNo, number) {

			results = append(results, SearchResult{
				Name:      account.Name,
				AccountNo: account.AccountNo,
			})

			if len(results) >= 10 {
				break
			}
		}
	}

	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(results)
}

// ---------- SEND MONEY ----------

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

	accountNumber := strings.TrimSpace(r.FormValue("account"))

	amount, err := strconv.ParseFloat(
		r.FormValue("amount"),
		64,
	)

	if err != nil || amount <= 0 {
		fmt.Fprintln(w, "Please enter a valid amount.")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	sender := findAccount(username)
	receiver := findAccountByNumber(accountNumber)

	if sender == nil || receiver == nil {
		fmt.Fprintln(w, "Receiver account not found.")
		return
	}

	if sender.AccountNo == receiver.AccountNo {
		fmt.Fprintln(w, "You cannot send money to yourself.")
		return
	}

	if sender.Balance < amount {
		fmt.Fprintln(w, "Insufficient balance.")
		return
	}

	sender.Balance -= amount
	receiver.Balance += amount

	now := time.Now().Format("02 Jan 2006, 15:04")

	transactions[username] = append(
		transactions[username],
		Transaction{
			Type:    "Sent",
			Amount:  amount,
			Details: "Sent to " + receiver.Name,
			Date:    now,
		},
	)

	transactions[receiver.Username] = append(
		transactions[receiver.Username],
		Transaction{
			Type:    "Received",
			Amount:  amount,
			Details: "Received from " + sender.Name,
			Date:    now,
		},
	)

	fmt.Fprintln(w, pageStart("Transfer Successful"))

	fmt.Fprintf(w, `
<div class="container">

<div class="card">

<div class="success">

<h1>Transfer Successful! ✅</h1>

<p>
You sent <strong>$%.2f</strong>
to <strong>%s</strong>.
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
		template.HTMLEscapeString(receiver.Name),
	)
}

// ---------- WITHDRAW PAGE ----------

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
placeholder="Enter amount"
required
>

<button type="submit">
Withdraw Money
</button>

</form>

</div>
</div>

</body>
</html>
`)
}

// ---------- WITHDRAW ----------

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
		fmt.Fprintln(w, "Please enter a valid amount.")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	account := findAccount(username)

	if account == nil {
		fmt.Fprintln(w, "Account not found.")
		return
	}

	if account.Balance < amount {
		fmt.Fprintln(w, `
<h1>Withdrawal Failed</h1>
<p>Insufficient balance.</p>
<a href="/withdraw">Try Again</a>
`)
		return
	}

	account.Balance -= amount

	now := time.Now().Format("02 Jan 2006, 15:04")

	transactions[username] = append(
		transactions[username],
		Transaction{
			Type:    "Withdrawal",
			Amount:  amount,
			Details: "Cash withdrawal",
			Date:    now,
		},
	)

	fmt.Fprintln(w, pageStart("Withdrawal Successful"))

	fmt.Fprintf(w, `
<div class="container">

<div class="card">

<div class="success">

<h1>Withdrawal Successful! ✅</h1>

<p>
You withdrew <strong>$%.2f</strong>.
</p>

</div>

<a href="/transactions">
<button>View Transactions</button>
</a>

</div>
</div>

</body>
</html>
`, amount)
}

// ---------- TRANSACTIONS ----------

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

	userTransactions := append(
		[]Transaction(nil),
		transactions[username]...,
	)

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Transactions"))

	fmt.Fprintln(w, `
<div class="container">

<div class="card">

<h1>📜 Transaction History</h1>
`)

	if len(userTransactions) == 0 {

		fmt.Fprintln(w, `
<div class="recipient">

<h3>No transactions yet.</h3>

<p>
Send money or withdraw money to see your activity here.
</p>

</div>
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

<p>
%s
</p>

<strong>
$%.2f
</strong>

<p>
<small>%s</small>
</p>

</div>
`,
				class,
				icon,
				template.HTMLEscapeString(t.Type),
				template.HTMLEscapeString(t.Details),
				t.Amount,
				template.HTMLEscapeString(t.Date),
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

// ---------- PROFILE ----------

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
		fmt.Fprintln(w, "Account not found.")
		return
	}

	name := account.Name
	user := account.Username
	number := account.AccountNo
	balance := account.Balance

	mu.Unlock()

	fmt.Fprintln(w, pageStart("Profile"))

	fmt.Fprintf(w, `
<div class="container">

<div class="card">

<h1>👤 My Profile</h1>

<p>
<strong>Name:</strong>
%s
</p>

<p>
<strong>Username:</strong>
%s
</p>

<p>
<strong>Account Number:</strong>
</p>

<div class="account-number">
%s
</div>

<p>
<strong>Balance:</strong>
$%.2f
</p>

</div>
</div>

</body>
</html>
`,
		template.HTMLEscapeString(name),
		template.HTMLEscapeString(user),
		template.HTMLEscapeString(number),
		balance,
	)
}

// ---------- LOGOUT ----------

func logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")

	if err == nil {

		mu.Lock()

		delete(sessions, cookie.Value)

		mu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			MaxAge:   -1,
			HttpOnly: true,
			Path:     "/",
		})
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------- 1000 TEST ACCOUNTS ----------

func createTestAccounts() {

	for i := 1; i <= 1000; i++ {

		username := fmt.Sprintf(
			"testuser%04d",
			i,
		)

		name := fmt.Sprintf(
			"Test User %04d",
			i,
		)

		accountNumber := generateAccountNumber()

		account := Account{
			Name:         name,
			Username:     username,
			PasswordHash: hashPassword("1234"),
			AccountNo:    accountNumber,
			Balance:      1000,
		}

		accounts = append(accounts, account)
	}
}

// ---------- MAIN ----------

func main() {

	accounts = []Account{}
	transactions = make(map[string][]Transaction)
	sessions = make(map[string]string)

	createTestAccounts()

	fmt.Println("==============================================")
	fmt.Println("       CALEB'S CITY MALL BANK")
	fmt.Println("==============================================")
	fmt.Println("1000 test accounts created.")
	fmt.Println("")
	fmt.Println("Example test account:")
	fmt.Println("Username: testuser0001")
	fmt.Println("Password: 1234")
	fmt.Println("")
	fmt.Println("Server:")
	fmt.Println("http://localhost:8080")
	fmt.Println("==============================================")

	http.HandleFunc("/", home)
	http.HandleFunc("/register", registerPage)
	http.HandleFunc("/login", login)
	http.HandleFunc("/send", sendPage)
	http.HandleFunc("/send-money", sendMoney)
	http.HandleFunc("/search", searchAccounts)
	http.HandleFunc("/withdraw", withdrawPage)
	http.HandleFunc("/withdraw-money", withdraw)
	http.HandleFunc("/transactions", transactionPage)
	http.HandleFunc("/profile", profilePage)
	http.HandleFunc("/logout", logout)

	err := http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println("Server error:", err)
	}
}