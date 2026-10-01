import math
import re
import secrets  # Cryptographically secure random number generator

##main
def Main():
  #get user input (for now)
  password = input("Enter password: ")
  #do checks and return score and any error messages
  passScore, errorMSG = checkPass(password)
  #password score output and issues found
  print(f"\nPassword score: {passScore}")
  if errorMSG:
    print("Issues found / Recommendations:")
    print(errorMSG)

#python file to create logic for checking passwords
def checkPass(password):
  #Block common weak passwords immediately
  valid, message, score = badPassCheck(password)
  if not valid:
    return 0, message

  #black error message to be added to later
  errorMSG = ""

  #Check Length (Essential Baseline)
  lengthCheck = passLengthCheck(password)
  if (lengthCheck == 0):
    errorMSG += "Password must be at least 12 characters long.\n"
  else:
    score += lengthCheck #rewarded for length

  #check for keyboard patterns (like qwerty, asdf, 1234, etc.)
  keyboard_patterns = {"qwerty", "asdf", "zxcv", "1234"}

  for pattern in keyboard_patterns:
    if pattern in password.lower():
        score -= 2
        errorMSG += "Password contains common keyboard patterns.\n"

  #check for repeated characters (like aaa, 111, etc.)
  for char in set(password):
    if password.count(char) > len(password) / 2:
        errorMSG += "Password contains excessive repetition.\n"

  # Alternative strength check
  #Process 3 Random Words (NCSC Model Alignment)
  detected_words = threeRandWords(password)
  words_count = len(detected_words)

  #Secure Passphrase Path
  if words_count >= 3 and lengthCheck == 1:
    if words_count > 3:
      score += 7
      print(f"-> Secure passphrase pattern: {words_count} random words detected ({', '.join(detected_words)})")
    else:
      score += 5
      print(f"-> Secure passphrase pattern: 3 random words detected ({', '.join(detected_words)})")
    return score, errorMSG

  #Standard Complexity Password Path
  else:
    # Run traditional character metrics validation
    scoreNum, msg = StandardValidation(password)
    score += scoreNum
    errorMSG += msg
    
    return score, errorMSG

def passLengthCheck(password):
  if (len(password) >= 12):
    return 1
  return 0

#compare to known weak passwords
def badPassCheck(password):
  #Use lower() comparison to prevent variations like "Password123" skipping the check
  try:
    with open("wordlists/10K-most-common.txt", "r", encoding="utf-8") as file:
      common_passwords = {line.strip() for line in file}
  except FileNotFoundError:
    # Fallback safeguard for testing environments incase file loading does not work
    common_passwords = {"password", "12345678", "qwerty", "123456", "qwerty12345", "qwerty1", "111111", "12345", "123456789", "secret", "123123", "abc123", "password1", "iloveyou", "admin", "welcome", "monkey", "login", "letmein", "princess", "sunshine", "football", "charlie", "donald", "michael", "shadow", "master", "jennifer", "jordan", "harley", "qwertyuiop", "asdfghjkl", "zxcvbnm", "passw0rd", "trustno1", "1234", "1234567", "1234567890", "password123", "1q2w3e4r", "1qaz2wsx", "qazwsx", "qwertyui", "qwertyuiop123", "qwerty123", "qwerty1", "qwerty12", "qwerty1234", "qwerty12345", "qwerty123456", "qwerty1234567", "qwerty12345678", "qwerty123456789", "password1!", "password!", "password@", "password#", "password$", "password%", "password^", "password&", "password*", "password(", "password)", "password-", "password_", "password+", "password=", "password{", "password}", "password[", "password]", "password|", "password\\", "password:", 'password"', 'password;', 'password<', 'password>', 'password,', 'password.', 'password?', 'password/', 'passw0rd!', 'passw0rd@', 'passw0rd#', 'passw0rd$', 'passw0rd%', 'passw0rd^', 'passw0rd&', 'passw0rd*', 'passw0rd(', 'passw0rd)', 'passw0rd-', 'passw0rd_', 'passw0rd+', 'passw0rd=', 'passw0rd{', 'passw0rd}', 'passw0rd[', 'passw0rd]', 'passw0rd|', 'passw0rd\\', 'passw0rd:', 'passw0rd"', 'passw0rd;', 'passw0rd<', 'passw0rd>', 'passw0rd,', 'passw0rd.', 'passw0rd?'}

  normalised = re.sub(r'[^a-z0-9]', '', password.lower())

  if normalised in common_passwords:
    return False, "Weak password: found in common password list", 0
  return True, "", 2

def segment_text(text, dictionary_set):
    """Recursive segmentation engine to find words inside solid text strings."""
    if not text:
        return []
    for i in range(len(text), 0, -1):
        prefix = text[:i]
        if prefix in dictionary_set:
            remainder = segment_text(text[i:], dictionary_set)
            if remainder is not None:
                return [prefix] + remainder
    return None

#3 random words - https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/three-random-words
#check for 3 random words
def threeRandWords(password):
    words_found = 0

    try:
      with open("wordlists/wordlist-eff-large.txt", "r", encoding="utf-8") as file:
        # Ignore 1-2 letter short-circuit strings (like 'an', 'is', 'to') to prevent code bypasses
        dictionary = {word.strip().lower() for word in file if len(word.strip()) >= 3}
    except FileNotFoundError:
      return []

    # Strip out punctuation, numbers, and spacing to isolate alphabetical segments
    clean_password = re.sub(r'[^a-zA-Z]', '', password).lower()
    words_found = segment_text(clean_password, dictionary)

    if words_found is not None:

      for word in words_found:
        if words_found.count(word) > 1:
          return []
      return words_found

    return []

#1 function for 12 chars, number, special character, Upercase, LowerCase
def StandardValidation(password):
  score = 0
  errorMSG = ""
  lower = False
  upper = False
  special = False
  number = False
  for char in password:
    if char.islower():
      lower = True
    elif char.isupper():
      upper = True
    elif char.isdigit():
      number = True
    elif not char.isalnum():
      special = True
  if not lower:
    errorMSG += "Password must contain at least one lowercase letter.\n"
  else:
    score += 1
  if not upper:
    errorMSG += "Password must contain at least one uppercase letter.\n"
  else:
    score += 2
  if not number:
    errorMSG += "Password must contain at least one number.\n"
  else:
    score += 2
  if not special:
    errorMSG += "Password must contain at least one special character.\n"
  else:
    score += 2
  return score, errorMSG

#generate 3 random words
def genPass():
  #load in the dictionary file
  pass

Main()