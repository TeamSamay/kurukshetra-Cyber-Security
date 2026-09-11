"""
Kurukshetra 2.0 Attacker Simulator (Member 2 Entrypoint).
Run:
  python attack.py --target <HONEYPOT_IP> --scenario mixed
  python attack.py --target <HONEYPOT_IP> --scenario ssh
  python attack.py --target <HONEYPOT_IP> --scenario web
  python attack.py --target <HONEYPOT_IP> --scenario api
"""

from attacker_simulator.cli import main

if __name__ == "__main__":
    main()
