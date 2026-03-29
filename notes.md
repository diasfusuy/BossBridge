## Notes
- In Foundry, makeAccount("") comes with two functionality we can use.
    1. operator.key
    2. operator.address
- with operator key, we can sign messages. 

- To prevent signature attacks use nonce (useNonce), deadline. add a parameter there. So when its signed it has special hash and will not work when attackers try again.