# Proof-Of-Work Auth
Example of an auth system that requires proof of work to process a login.

## Description
An example client script and server that runs a dummy auth system which requires proof of work to perform a login.

By using proof of work, a server can prevent a brute force password attack by requiring that the client do some non-trivial amount of work in order for the server to process the login. The example in this repository is the same system used by Bitcoin: the user must provide some data which, when hashed, has some number of leading zeros. 

To initiate a login, a client visits /login/init and retrieves some `randomData`, a `target` number of leading 0 bits, and a `token`. The client must then find a string prefixed with `<randomData>:<email>:<password>` which, when hashed using SHA256, results in a hash string with `target` leading 0 bits. The client must on average perform a significant amount of work which the server can validate in a short amount of time. 

The `token` is a standard signed JWT token - it is used to ensure that the `randomData` did actually originate in the server, and _should_ be used to enforce an expiry time on the `randomData` so it can't be reused (this would allow an attacker to precompute many hashes). This enforcement is not present in this example. 

## Repository structure
### `server` 
A simple auth server written in [golang](https://golang.org). All code exists in a single `main.go` file. Exposes the following endpoints:

- `POST /register`
    - Inserts a new user into the dummy database. Accepts JSON with format {"email": string, "password": string}. Return 200 on successful registration.

- `GET /login/init`
    - Returns a JSON object with {"target": number, "data": string, "token": string}. Client uses this information to create their proof of work as described above.

- `POST /login`
    - Attempt to login with the provided credentials. Accepts JSON with format {"email": string, "password": string, "proof_of_work": string}. Requires that the `Authorization` header be present, using the `Bearer` scheme, and a token retrived on `/login/init`

#### Running the server
Create a file called `.env` in the `server` directory. `.env` should contain `SECRET_KEY=<any secret key>`. Then run the command `go run main.go` from the `server` directory and the server will start on port `8080`.

### `client`
A client script written in [Python 3](https://www.python.org/) which exhibits the login workflow. Install all the dependencies listed in `client/requirements.txt` using [pip](https://pypi.org/project/pip/) or similar and then run `python client.py`

