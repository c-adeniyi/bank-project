package main

import (
	"encoding/json"
	"net/http"
)

type Account struct {
	Name    string  `json:"name"`
	Balance float64 `json:"balance"`
}

var account = Account{
	Name:    "Caleb",
	Balance: 1000,
}

func balanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
}

func depositHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Amount float64 `json:"amount"`
	}

	json.NewDecoder(r.Body).Decode(&data)

	account.Balance += data.Amount

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
}

func withdrawHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Amount float64 `json:"amount"`
	}

	json.NewDecoder(r.Body).Decode(&data)

	if data.Amount > account.Balance {
		http.Error(w, "Insufficient balance", http.StatusBadRequest)
		return
	}

	account.Balance -= data.Amount

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(account)
}

func main() {
	http.HandleFunc("/balance", balanceHandler)
	http.HandleFunc("/deposit", depositHandler)
	http.HandleFunc("/withdraw", withdrawHandler)

	println("Banking server running on http://localhost:8080")

	http.ListenAndServe(":8080", nil)