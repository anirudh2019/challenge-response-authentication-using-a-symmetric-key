# challenge-response-authentication-using-a-symmetric-key-cipher
- First run verifier.py, enter shared key. Now it starts listening to new connections.
- Now run claimant.py, enter shared key then it automatically connects to verifier.
- Now you have options to choose method of Authentication at claimant side. Type that number, then you get to know whether claimant is authenticated or not.
- If shared key of both  matches, Authentication will be success or else it fail.

Note:
1. As method of encryption used here is Columnar Transposition, ensure that there is no repeatition of characters in shared key and are of same length.
2. Here shared key of both may mismatch(which is actually not practical, just to show you the case when Authentication fails) which leads to failed Authentication.
