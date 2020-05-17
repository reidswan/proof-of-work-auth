package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// User - user entry for fake database
type User struct {
	email        string
	passwordHash []byte
}

// RegisterRequest - JSON struct for a request on the /register endpoint
type RegisterRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginRequest - JSON struct for a request on the /login endpoint
type LoginRequest struct {
	Email       string `json:"email" bind:"required"`
	Password    string `json:"password" bind:"required"`
	ProofOfWork string `json:"proof_of_work" bind:"required"`
}

// ProofOfWorkClaims - used to create a signed JWT to be submitted with a proof of work
type ProofOfWorkClaims struct {
	RandomData string `json:"data"`
	Target     uint   `json:"target"` // the hash must start with this many zeros
	jwt.StandardClaims
}

var usersDb = []User{}
var secretKey string
var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

const secretKeyVarName = "SECRET_KEY"
const leadingZeros = uint(10)                                            // the user must create a hash of the random data with this many leading 0s as proof of work
const leadingZeroBytes = leadingZeros / 8                                // precompute the number of leading 0 bytes required
const maxRemainingByte = ^byte(0) >> (leadingZeros - 8*leadingZeroBytes) // the first non-zero byte of the hash should be <= this amount
const randomDataSize = 12

func randomString(n int) string {
	generatedString := make([]rune, n)
	for i := range generatedString {
		generatedString[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(generatedString)
}

// insertUser - put a user into our "db" if they don't already exist
func insertUser(email, password string) error {
	// check the email is not in use
	email = strings.ToLower(email)
	for _, user := range usersDb {
		if strings.ToLower(user.email) == email {
			return fmt.Errorf("User with email already exists: %s", email)
		}
	}

	// store the hash of the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	usersDb = append(usersDb, User{email, passwordHash})

	return nil
}

// checkUser - given credentials, check they match a user in our "db"
func checkUser(email, password string) (bool, error) {
	// find a user with that email
	email = strings.ToLower(email)
	var foundUser *User = nil
	for _, user := range usersDb {
		if strings.ToLower(user.email) == email {
			foundUser = &user
		}
	}

	if foundUser == nil {
		return false, fmt.Errorf("Could not find user with email %s", email)
	}

	// check that passwords match
	err := bcrypt.CompareHashAndPassword(foundUser.passwordHash, []byte(password))
	return err == nil, err
}

// handle the /register endpoint
func registerHandler(c *gin.Context) {
	var json RegisterRequest
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// should do some real validation here
	if len(json.Email) == 0 || len(json.Password) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password fields must be non-empty"})
		return
	}

	err := insertUser(json.Email, json.Password)
	if err != nil {
		if strings.HasPrefix(err.Error(), "User with email already exists") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		}
		return
	}

	c.JSON(200, gin.H{
		"message": "User registered successfully",
	})
}

// handle the /login endpoint
func loginHandler(c *gin.Context) {
	var json LoginRequest

	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := getTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check the proof of work
	err = checkProofOfWork(token, json.Email, json.Password, json.ProofOfWork)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	loginSuccess, err := checkUser(json.Email, json.Password)
	if err != nil || !loginSuccess {
		var errorMessage string
		if err != nil {
			errorMessage = err.Error()
		} else { // !loginSuccess
			errorMessage = "Invalid email or password provided"
		}
		c.JSON(http.StatusUnauthorized, gin.H{"message": errorMessage})
		return
	}

	// typically some auth token like a JWT would be returned to the user here
	c.JSON(200, gin.H{"message": "Successfully logged in!"})
}

// handle the /login/init endpoint; user retrieves a JWT and random data for proof of work
func initiateLoginHandler(c *gin.Context) {
	randomData := randomString(randomDataSize)
	token, err := generateToken(randomData, leadingZeros)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to initiate login"})
	}

	c.JSON(200, gin.H{"token": token, "data": randomData, "target": leadingZeros})
}

// get <token> from header `Authorization: Bearer <token>`
func getTokenFromHeader(c *gin.Context) (string, error) {
	authorizationHeader := strings.TrimSpace(c.Request.Header.Get("Authorization"))

	if len(authorizationHeader) == 0 {
		return "", errors.New("No Authorization header present")
	}

	split := strings.Split(authorizationHeader, " ")
	if len(split) != 2 || strings.ToLower(split[0]) != "bearer" {
		return "", errors.New("Authorization header is malformed; expecting 'Bearer <token>'")
	}

	return split[1], nil
}

func generateToken(randomData string, target uint) (string, error) {
	claims := ProofOfWorkClaims{
		RandomData:     randomData,
		Target:         target,
		StandardClaims: jwt.StandardClaims{},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString([]byte(secretKey))
	return signedToken, err
}

// note: does not check the expiry claim on the JWT; this claim should be checked
// in a real proof of work system to prevent an attacker from precomputing hashes
func validateJwt(receivedJwt string) (ProofOfWorkClaims, error) {
	token, err := jwt.ParseWithClaims(receivedJwt, &ProofOfWorkClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return ProofOfWorkClaims{}, err
	}

	claims, ok := token.Claims.(*ProofOfWorkClaims)
	if !ok {
		return ProofOfWorkClaims{}, errors.New("Failed to parse the claims")
	}
	return *claims, nil
}

// checkProofOfWork() does three things
// - ensure that the JWT is valid
// - ensure that the proof of work data is prefixed with `<randomData>:<email>:<password>`
// - ensure that SHA256 hash of the proof of work data is less than the target
// returns nil err if and only if these three conditions all hold
func checkProofOfWork(jwt, email, password, proofOfWorkData string) error {
	claims, err := validateJwt(jwt)
	if err != nil {
		return errors.New("Supplied token is invalid")
	}

	prefix := fmt.Sprintf("%s:%s:%s", claims.RandomData, email, password)
	if !strings.HasPrefix(proofOfWorkData, prefix) {
		return errors.New("Submitted proof of work data does not begin with the correct prefix; prefix should be <data>:<email>:<password>")
	}

	insufficientLeadingZeros := errors.New("Hash of proof of work has insufficient leading zero bits")
	hashed := sha256.Sum256([]byte(proofOfWorkData))
	// check that the first `leadingZeros` bits are 0
	for i := uint(0); i < leadingZeroBytes; i++ {
		if hashed[i] != 0 {
			return insufficientLeadingZeros
		}
	}

	// the remaining 0 bits lead the byte at position `zeroBytes`
	if leadingZeros%8 != 0 {
		// there are remaining bits
		if hashed[leadingZeroBytes] > maxRemainingByte {
			return insufficientLeadingZeros
		}
	}

	return nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load .env file", err)
	}

	var present bool
	secretKey, present = os.LookupEnv(secretKeyVarName)
	if !present {
		log.Fatalf("Environment variable %s is not set", secretKeyVarName)
	}

	// check that the leadingZeros variable is sane
	bitsInSha256 := uint(32 * 8)
	if leadingZeros >= bitsInSha256 {
		log.Fatalf("%d leading zeros is not possible to achieve with SHA256", leadingZeros)
	}

	router := gin.Default()
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.GET("/login/init", initiateLoginHandler)
	log.Fatal(router.Run())
}
