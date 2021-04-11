package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	verifyTokenSize = 6
	resetTokenSize  = 6
)

// RegisterRoutes initializes the api endpoints and maps the requests to specific functions. The API will
// make use of the passed in Mailer and database connection. What HTTP methods would be most appropriate
// for each route?
func RegisterRoutes(router *mux.Router, m Mailer, db *sql.DB) {
	router.HandleFunc("/api/auth/signup", signup(m, db)).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/signin", signin(db)).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/logout", logout).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/verify", verify(db)).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/sendreset", sendReset(m, db)).Methods(/*YOUR CODE HERE*/)
	router.HandleFunc("/api/auth/resetpw", resetPassword(db)).Methods(/*YOUR CODE HERE*/t)
}

// A function that handles signing a user up for Bearchat.
func signup(m Mailer, DB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtain the credentials from the request body

		// Check if the username already exists
		
		// Check for any errors

		// Check boolean returned from query

		// Check if the email already exists
		
		// Check for any errors

		// Check boolean returned from query

		// Hash the password using bcrypt and store the hashed password in a variable
		pass, err := bcrypt.GenerateFromPassword([]byte(/*YOUR CODE HERE*/), bcrypt.DefaultCost)

		// Check for errors during hashing process
		if err != nil {
			http.Error(w, "error preparing password for storage", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Create a new user UUID, convert it to string, and store it within a variable

		// Create new verification token with the default token size (look at GetRandomBase62 and our constants)

		// Store credentials in database

		// Check for errors in storing the credentials

		// Generate an access token, expiry dates are in Unix time
		accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
		var accessToken string
		accessToken, err = setClaims(AuthClaims{
			UserID: /*YOUR CODE HERE*/,
			StandardClaims: jwt.StandardClaims{
				Subject:   "access",
				ExpiresAt: accessExpiresAt.Unix(),
				Issuer:    defaultJWTIssuer,
				IssuedAt:  time.Now().Unix(),
			},
		})

		// Check for error in generating an access token
		if err != nil {
			http.Error(w, "error generating access token", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Set the cookie, name it "access_token"
		http.SetCookie(w, &http.Cookie{
			Name:    "access_token",
			Value:   accessToken,
			Expires: accessExpiresAt,
			// Since our website does not use HTTPS, we have this commented out.
			// However, in an actual service you would definitely want this so no
			// cookies get stolen!
			//Secure:   true,
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

		// Send verification email. Fill in the blank with the email of the user.
		err = m.SendEmail(/*YOUR CODE HERE*/, "Email Verification", "user-signup.html", map[string]interface{}{"Token": verifyToken})
		if err != nil {
			http.Error(w, "error sending verification email", http.StatusInternalServerError)
			log.Print(err.Error())
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func signin(DB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Store the credentials in a instance of Credentials

		// Check for errors in storing credntials
		
		// Get the hashedPassword and userId of the user
		
		// Process errors associated with emails

		// Check if hashed password matches the one corresponding to the email
		err = bcrypt.CompareHashAndPassword([]byte(/*YOUR CODE HERE*/), []byte(/*YOUR CODE HERE*/))

		// Check error in comparing hashed passwords
		if err != nil {
			http.Error(w, "incorrect password", http.StatusBadRequest)
			return
		}

		// Generate an access token and set it as a cookie
		accessExpiresAt := time.Now().Add(DefaultAccessJWTExpiry)
		var accessToken string
		accessToken, err = setClaims(AuthClaims{
			UserID: "",
			StandardClaims: jwt.StandardClaims{
				Subject:   "access",
				ExpiresAt: accessExpiresAt.Unix(),
				Issuer:    defaultJWTIssuer,
				IssuedAt:  time.Now().Unix(),
			},
		})

		//Check for error in generating an access token

		//Set the cookie, name it "access_token"
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			Expires:  accessExpiresAt,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Path:     "/",
		})

		// Generate a refresh token and set it as a cookie
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

		http.SetCookie(w, &http.Cookie{
			Name:    "refresh_token",
			Value:   refreshToken,
			Expires: refreshExpiresAt,
			Path:    "/",
		})
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Set the access_token and refresh_token to have an empty value and set their expiration date to anytime in the past
	var expiresAt = /*YOUR CODE HERE*/
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Expires: expiresAt})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Expires: expiresAt})
}

func verify(DB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		// Check that valid token exists
		if len(token) == 0 {
			http.Error(w, "url param 'token' is missing", http.StatusInternalServerError)
			log.Print("url param 'token' is missing")
			return
		}

		// Obtain the user with the verifiedToken from the query parameter and set their verification status to the integer "1"
		
		// Check for errors in executing the previous query
		
		// Make sure there were some rows affected
		// Check: https://golang.org/pkg/database/sql/#Result
		// This is to make sure that there was an email that was actually changed by our query.
		// If no rows were affected return an error of type "StatusBadRequest"

	}
}

func sendReset(m Mailer, DB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the email from the body (decode into an instance of Credentials)

		// Check for errors decoding the object

		// Check for other miscallenous errors that may occur
		// What is considered an invalid input for an email?
		
		// Generate reset token

		// Obtain the user with the specified email and set their resetToken to the token we generated
		
		// Check for errors executing the queries

		// Send verification email
		err = m.SendEmail(/*YOUR CODE HERE*/, "BearChat Password Reset", "password-reset.html", map[string]interface{}{"Token": token})
		if err != nil {
			http.Error(w, "error sending verification email", http.StatusInternalServerError)
			log.Print(err.Error())
		}
	}
}

func resetPassword(DB *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from query params

		// Get the username, email, and password from the body
		
		// Check for errors decoding the body

		// Check for invalid inputs, return an error if input is invalid

		// Check if the username and token pair exist
		
		// Check for errors executing the query
		
		// Check exists boolean. Call an error if the username-token pair doesn't exist

		// Hash the new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(/*YOUR CODE HERE*/), bcrypt.DefaultCost)

		// Check for errors in hashing the new password
		if err != nil {
			http.Error(w, "password preparation failed", http.StatusInternalServerError)
			log.Print(err.Error())
			return
		}

		// Input new password and clear the reset token (set the token equal to empty string)

	}
}
