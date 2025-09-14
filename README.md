# CS50 Finance

This project was an opportunity for me to apply object-oriented programming principles and leverage existing frameworks to build a functional web application.

Through this project, I was able to:

* **Develop a full-stack web application** using Python, Flask, and SQLite.
* **Implement key features** including user registration with secure password hashing, stock buying and selling with transaction history, and a dynamic portfolio display.
* **Practice database design** by creating and managing multiple tables to store user data and transaction records.

## Basic Instructions

Clone the project.

Open the project in your preferred IDE.

Run the application with Flask:
`flask run`

Navigate to the URL provided by Flask.

## Usage Instructions

* **Register:** To get started, click on the **Register** link to create a new account. You'll need to provide a username and a password.
* **Login:** After registering, you can log in to your account.
* **Quote:** Use the **Quote** feature to look up the current price of a stock by entering its symbol.
* **Buy:** To purchase shares, enter the stock's symbol and the number of shares you want to buy. The app will calculate the total cost and debit it from your cash balance.
* **Sell:** To sell shares you own, select the stock from the dropdown menu and enter the number of shares you wish to sell. The app will credit your cash balance with the sale amount.
* **Portfolio:** The main **Portfolio** page shows a summary of all the stocks you own, their current prices, and the total value of your holdings. It also displays your current cash balance.
* **History:** The **History** page provides a detailed log of all your past transactions, including buys and sells, with timestamps.
