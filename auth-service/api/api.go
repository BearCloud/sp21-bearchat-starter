package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/sendgrid/sendgrid-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	verifyTokenSize = 6
	resetTokenSize  = 6
)

// RegisterRoutes initializes the api endpoints and maps the requests to specific functions
func RegisterRoutes(router *mux.Router) error {
	router.HandleFunc("/api/auth/signup", signup).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/signin", signin).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/logout", logout).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/verify", verify).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/sendreset", sendReset).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/resetpw", resetPassword).Methods(/*YOUR CODE HERE*/)

	// Load sendgrid credentials
	err := godotenv.Load()
	if err != nil {
		return err
	}

	sendgridKey = os.Getenv("SENDGRID_KEY")
	sendgridClient = sendgrid.NewSendClient(sendgridKey)
	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	// Obtain the credentials from the request body and perform checks on the credentials.
	// YOUR CODE HERE

	// Hash the password using bcrypt and store the hashed password in a variable.
	// Take a look at the spec if you do not know how.
	// YOUR CODE HERE

	// Create a new user UUID and new verification token with the default token size (look at GetRandomBase62 and our constants).
	// Then, store all necessary information into database.
	// Hint: For the new user UUID, what type should it be?
	// YOUR CODE HERE

	// Generate an access token, expiry dates are in Unix time
	accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
	var accessToken string
	accessToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "access",
			ExpiresAt: accessExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	// Check for error in generating an access token
	// YOUR CODE HERE

	// Set the cookie, name it "access_token"
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   accessToken,
		Expires: accessExpiresAt,
		//Secure:   true,	// Since our website does not use HTTPS, this will make the cookie not send.
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

	// Generate refresh token
	var refreshExpiresAt = time.Now().Add(DefaultRefreshJWTExpiry)
	var refreshToken string
	refreshToken, err = setClaims(AuthClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			Subject:   "refresh",
			ExpiresAt: refreshExpiresAt.Unix(),
			Issuer:    defaultJWTIssuer,
			IssuedAt:  time.Now().Unix(),
		},
	})

	if err != nil {
		http.Error(w, "error creating refreshToken", http.StatusInternalServerError)
		log.Print(err.Error())
		return
	}

	// Set the refresh token ("refresh_token") as a cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   refreshToken,
		Expires: refreshExpiresAt,
		Path:    "/",
	})

	// Send verification email
	err = SendEmail(creds.Email, "Email Verification", "user-signup.html", map[string]interface{}{"Token": verifyToken})
	if err != nil {
		http.Error(w, "error sending verification email", http.StatusInternalServerError)
		log.Print(err.Error())
	}

	w.WriteHeader(http.StatusCreated)
}

func signin(w http.ResponseWriter, r *http.Request) {
	// Store the credentials in a instance of Credentials. Then, from the credentials, acquire necessary information for sign in purposes.
	// Also remember to check if the password is correct. Hashing?
	// Hint: What information do you usuaully need to sign in? Use the email to differentiate users in the database.
	// YOUR CODE HERE



	// Generate an access token  and set it as a cookie (Look at signup and feel free to copy paste!)
	// YOUR CODE HERE

	// Generate a refresh token and set it as a cookie (Look at signup and feel free to copy paste!)
	// YOUR CODE HERE

}

func logout(w http.ResponseWriter, r *http.Request) {
	// Set the access_token and refresh_token to have an empty value and set their expiration date to anytime in the past
	var expiresAt = /*YOUR CODE HERE*/
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Expires: /*YOUR CODE HERE*/})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Expires: /*YOUR CODE HERE*/})
}

func verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	// Check that valid token exists
	if len(token) == 0 {
		http.Error(w, "url param 'token' is missing", /*YOUR CODE HERE*/)
		log.Print("url param 'token' is missing")
		return
	}

	// Obtain the user with the verifiedToken from the query parameter and set their verification status to the integer "1"
	result, err := DB.Exec("UPDATE users SET verified=1 WHERE verifiedToken=?", token)

	// Check for errors in executing the previous query
	// YOUR CODE HERE

	// Make sure there were some rows affected
	// Check: https://golang.org/pkg/database/sql/#Result
	// This is to make sure that there was an email that was actually changed by our query
	// if no files were affected return an error of type "StatusBadRequest"
	
}

func sendReset(w http.ResponseWriter, r *http.Request) {
	// Get the email from the body (decode into an instance of Credentials)
	// YOUR CODE HERE

	// Generate reset token
	token := GetRandomBase62(resetTokenSize)

	// Obtain the user with the specified email and set their resetToken to the token we generated
	// YOUR CODE HERE

	// Send verification email
	err = SendEmail(creds.Email, "BearChat Password Reset", "password-reset.html", map[string]interface{}{"Token": token})
	if err != nil {
		http.Error(w, "error sending verification email", http.StatusInternalServerError)
		log.Print(err.Error())
	}
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	// Get token from query params
	token := r.URL.Query().Get("token")

	// Get the username, email, and password from the body. Make sure to account for invalid inputs
	// and that the username and token pair exists.
	// YOUR CODE HERE

	// Hash the new password
	// YOUR CODE HERE

	// Input new password and clear the reset token (set the token equal to empty string)
	_, err = DB.Exec("UPDATE users SET hashedPassword=?, resetToken=? WHERE username=?", hashedPassword, "", username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err.Error())
	}

	// Put the user in the redis cache to invalidate all current sessions (NOT IN SCOPE FOR PROJECT), leave this comment for future reference
}
