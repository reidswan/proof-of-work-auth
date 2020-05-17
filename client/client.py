import requests
import random
import hashlib
from typing import Tuple

alphabet = [chr(i) for i in range(ord('A'), ord('Z') + 1)] + [chr(i) for i in range(ord('a'), ord('z') + 1)]

def random_string(size: int)-> str:
    if size <= 0:
        raise Exception("Can't generate a string with fewer than 1 char")
    
    return ''.join(random.choice(alphabet) for i in range(size))

def register_user()-> Tuple[str, str]:
    """Register a new user on localhost:8080/register, returning the email and password"""
    email = f"{random_string(8)}@example.com"
    password = random_string(random.randint(8, 16))

    register_data = {
        "email": email,
        "password": password
    }

    response = requests.post(
        "http://localhost:8080/register",
        json=register_data
    )
    response.raise_for_status()
    return (email, password)


def login(email: str, password: str) -> bool: 
    """Login to a proof of work system"""
    init_login_data_response = requests.get("http://localhost:8080/login/init")
    init_login_data_response.raise_for_status()
    init_login_data = init_login_data_response.json()
    
    print(f"Initiated login: {init_login_data}")
    
    token = init_login_data["token"]
    data = init_login_data["data"]
    target = init_login_data["target"]

    prefix = make_prefix(data, email, password)
    
    # find the proof of work
    proof, iterations = find_hash(prefix, target)
    print(f"Took {iterations} iterations to find the proof")
    
    headers = {
        "Authorization": f"Bearer {token}"
    }

    body = {
        "email": email,
        "password": password,
        "proof_of_work": proof
    }

    response = requests.post(
        "http://localhost:8080/login",
        headers=headers,
        json=body
    )
    try:
        response.raise_for_status()
    except Exception as e:
        print("Failed to login:", e)
        return False

    return True


def make_prefix(data: str, email: str, password: str) -> str:
    return f"{data}:{email}:{password}"


def check_hash(hash: bytes, leading_zeros: int)-> bool:
    """Check that the provided hash is prefixed with at least `leading_zeros` zero bits"""
    if leading_zeros >= 32 * 8:
        raise Exception(f"Requirement of {leading_zeros} leading zero bits is impossible; max is {32 * 8}")
    
    # convert bits to bytes, flooring
    leading_zero_bytes = leading_zeros // 8
    # the bits that leak into the first non-zero byte
    remaining_bits = leading_zeros - leading_zero_bytes * 8
    # take 0b11111111 and shift `remaining_bits` leading 0s into it
    # if the byte at index `leading_zero_bytes` exceeds this, there are insufficient leading 0s
    max_first_nonzero_byte = (2 ** 8 - 1) >> remaining_bits
    
    for i in range(leading_zero_bytes):
        if hash[i] != 0:
            return False
    if hash[leading_zero_bytes] > max_first_nonzero_byte:
        return False
    
    return True


def find_hash(prefix_data: str, leading_zeros: int)-> Tuple[str, int]:
    """
    Iterate until we find a number which, when appended to prefix_data,
    results in a hash with `leading_zeros` 0 bits as a prefix
    """
    i = 0 
    init_hasher = hashlib.sha256()
    init_hasher.update(prefix_data.encode())
    while 1:
        hasher = init_hasher.copy()
        hasher.update(str(i).encode())
        hash_bytes = hasher.digest()
        if check_hash(hash_bytes, leading_zeros):
            return f"{prefix_data}{i}", i
        i += 1


def main():
    # register a user
    email, password = register_user()
    print(f"Created user with email {email}")
    login_success = login(email, password)
    if login_success:
        print("Successfully logged in!")
    else:
        print("Failed to log in")
    

if __name__ == '__main__':
    main()