curl http://127.0.0.1:8081/dev/create-user \
-H "Content-Type: application/json" \
-d { "username": "simon", "password": "Passw0rd!", "email": "simon@example.com", "given_name": "Simon", "family_name": "Lee" }
