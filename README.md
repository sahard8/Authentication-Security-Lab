#### Ethical disclosure: 
This research is part of a student-led controlled cybersecurity project, conducted for educational purposes only.

All actions are performed ethically and responsibly.

---

## About the project

This project investigates the effectiveness of password hashing algorithms and authentication security mechanisms against Brute Force and Password Spraying attacks.
We developed a Python-based authentication server using Flask and SQLite, alongside an attack simulation client, to conduct controlled experiments and evaluate different security configurations.

The research compares:

**Password Hashing:** SHA-256, bcrypt, and Argon2id.

**Security Mechanisms:** Rate Limiting, Account Locking, CAPTCHA, and TOTP.

**Performance Metrics:** Attack success rates, attempts per second, authentication latency, CPU utilization, and memory consumption. 

#### Key Findings : 
**Password Hashing:** SHA-256 achieved the highest authentication throughput, while bcrypt significantly reduced attack speed at the cost of higher CPU utilization. Argon2id demonstrated intermediate performance with greater memory consumption under the tested configurations.

**Rate Limiting:** Significantly slowed Brute Force attacks but was less effective against Password Spraying.

**TOTP:** Prevented successful unauthorized authentication in both tested attack scenarios.

**Layered Security:** The combination of Argon2id + Rate Limiting + TOTP provided the strongest overall protection among the tested configurations.

These findings are based on experiments conducted in a controlled laboratory environment.

### Research Documentation
- [Research Report (PDF)](docs/Authentication_Security_Research_Report.pdf)
- [Project Presentation (PDF)](docs/Authentication_Security_Presentation.pdf)

*Both documents are available in Hebrew.*

### Password Classification Method

For the purpose of controlled experimentation, the 30 passwords are classified into three categories (Weak, Medium, High) based on a syntactic complexity score.  
This classification is used to ensure clear and reproducible differences between password groups.

Each password is evaluated against the following criteria:
1. Password length is at least 8 characters
2. Contains lowercase English letters (a–z)
3. Contains uppercase English letters (A–Z)
4. Contains digits (0–9)
5. Contains special symbols

The final classification is determined by the total number of satisfied criteria:
- 1 criterion  → Weak password
- 2–3 criteria → Medium password
- More than 3 criteria → Strong password

This scoring method measures syntactic complexity only.

The full password dataset, including usernames, passwords, complexity scores, and classification rationale, is provided in the csv file:

##### password_dataset.csv

**Group seed** - used throughout the project to make sure its unique and original. 
14320970

---


## Installation & Usage

### Prerequisites :
Python 3
Git (optional, if downloading the project as a ZIP)

### Setup
Clone the repository:

git clone https://github.com/sahard8/Authentication-Security-Lab.git
cd Authentication-Security-Lab

Install the required dependencies:

pip install -r requirements.txt

### Config file explained : 

1. Open two terminals and navigate to the server directory in both.
2. Now change the configurations in the `config.json` file to the ones you need. 
3. After setting up all of the desired settings, run server.py in the 1st terminal by typing `py server.py` 
4. Then run attacks.py in the 2nd terminal by typing : `py attacks.py `
5. When you want to stop an experiment in the middle (instead of waiting until the end) use "ctrl + c" in both terminals. 
6. For the program to work smoothly , please stop both of the terminals and run them again for the changes to work as needed. ( e.g for switching from "brute force" option to simulating "password spraying " you would need to stop the server as well and not only attacks.py )

---

### Config file explained : 
Inside the server directory , all of the configurations are placed in `config.json` file 

The possible values for each setting are as follows :

1. "`hash_mode`" - The options are `sha256`, `Argon2`, `bycrypt`
2. "`attack_mode`" - 
   `brute_force` or `password_spraying`
3. "`attacked_username`" - any username from the database / dataset.csv
4. All `enabled` flags - true or false
5. `"rate_limiting"`: 
	1. "`max_attempts`" - the amount of attempts it takes for the user to be temporarily locked (any positive number)
	2. "`lockout_duration_seconds`" - for how long the user will locked for after trying out `max_attempts` amount of times to login unsuccessfully (any positive number)
6. "`account_lockout`" :
	1. "`max_attempts`" - the amount of attempts it takes for the user to be **permanently** locked (any positive number)
7. "`captcha`" :
	1. "`number_of_failed_attempts`" : - the amount of attempts it takes for the user to be prompted for a captcha token (any positive number)
	2. "`user_has_token`": true / false --> if the user has a token the captcha is resolved faster and the attacker is slowed down for significantly less amount of time
	3. "`delay_for_correct_token_seconds`" - for how long the user will be delayed for after trying out `number_of_failed_attempts` amount of times to login unsuccessfully, if the user has the token
	4. "`delay_for_incorrect_token_seconds`": same as previous option but for `user_has_token` == false 

### The End !
