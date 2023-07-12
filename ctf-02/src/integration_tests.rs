#[cfg(test)]
pub mod tests {

    use crate::{
        contract::{DENOM, LOCK_PERIOD},
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
        state::UserInfo,
    };
    use cosmwasm_std::{coin, Addr, Empty, Uint128};
    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    pub fn challenge_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    pub const USER: &str = "user";
    pub const HACKER: &str = "hacker";
    pub const ADMIN: &str = "admin";

    pub fn proper_instantiate() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {};
        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        (app, contract_addr)
    }

    pub fn mint_tokens(mut app: App, recipient: String, amount: Uint128) -> App {
        app.sudo(cw_multi_test::SudoMsg::Bank(
            cw_multi_test::BankSudo::Mint {
                to_address: recipient,
                amount: vec![coin(amount.u128(), DENOM)],
            },
        ))
        .unwrap();
        app
    }

    #[test]
    fn basic_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let amount = Uint128::new(1_000);

        app = mint_tokens(app, USER.to_string(), amount);
        let sender = Addr::unchecked(USER);

        // deposit funds
        let msg = ExecuteMsg::Deposit {};
        app.execute_contract(
            sender.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(amount.u128(), DENOM)],
        )
        .unwrap();

        // no funds left
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, Uint128::zero());

        // query user
        let msg = QueryMsg::GetUser {
            user: (&USER).to_string(),
        };
        let user: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(user.total_tokens, amount);

        // cannot stake more than deposited
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128() + 1,
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // normal stake
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // query voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, amount.u128());

        // cannot unstake before maturity
        let msg = ExecuteMsg::Unstake {
            unlock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // cannot withdraw while staked
        let msg = ExecuteMsg::Withdraw { amount };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();

        // fast forward time
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // normal unstake
        let msg = ExecuteMsg::Unstake {
            unlock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // no more voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, 0_u128);

        // normal withdraw
        let msg = ExecuteMsg::Withdraw { amount };
        app.execute_contract(sender, contract_addr, &msg, &[])
            .unwrap();

        // funds are received
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, amount);
    }

    // #[test]
    // fn test_withdraw_accounting() {
    //     let (mut app, contract_addr) = proper_instantiate();

    //     let amount = Uint128::new(1_000);

    //     app = mint_tokens(app, USER.to_string(), amount);
    //     app = mint_tokens(app, HACKER.to_string(), amount);
    //     let sender = Addr::unchecked(USER);
    //     let hacker = Addr::unchecked(HACKER);

    //     // deposit funds for user
    //     let msg = ExecuteMsg::Deposit {};
    //     app.execute_contract(
    //         sender.clone(),
    //         contract_addr.clone(),
    //         &msg,
    //         &[coin(amount.u128(), DENOM)],
    //     )
    //     .unwrap();

    //     // deposit funds for hacker
    //     let msg = ExecuteMsg::Deposit {};
    //     app.execute_contract(
    //         hacker.clone(),
    //         contract_addr.clone(),
    //         &msg,
    //         &[coin(amount.u128(), DENOM)],
    //     )
    //     .unwrap();

    //     // The hacker stakes 70 tokens
    //     let res = app.execute_contract(
    //         hacker.clone(),
    //         contract_addr.clone(),
    //         &ExecuteMsg::Stake { lock_amount: 70 },
    //         &[],
    //     );
    //     assert!(res.is_ok());

    //     // fast forward time
    //     app.update_block(|block| {
    //         block.time = block.time.plus_seconds(LOCK_PERIOD);
    //     });

    //     // The hacker unstakes 50 tokens
    //     let res = app.execute_contract(
    //         hacker.clone(),
    //         contract_addr.clone(),
    //         &ExecuteMsg::Unstake { unlock_amount: 50 },
    //         &[],
    //     );
    //     assert!(res.is_ok());

    //     // The user withdraws 90 tokens
    //     let res = app.execute_contract(
    //         hacker.clone(),
    //         contract_addr.clone(),
    //         &ExecuteMsg::Withdraw {
    //             amount: Uint128::from(90u128),
    //         },
    //         &[],
    //     );
    //     assert!(res.is_ok());

    //     // funds are received
    //     let balance = app.wrap().query_balance(hacker, DENOM).unwrap().amount;
    //     assert_eq!(balance, Uint128::from(90u128));

    //     // query user for voting power
    //     // should be 10 tokens, not 20 tokens
    //     let msg = QueryMsg::GetVotingPower {
    //         user: (&HACKER).to_string(),
    //     };
    //     let voting_power: u128 = app
    //         .wrap()
    //         .query_wasm_smart(contract_addr.clone(), &msg)
    //         .unwrap();
    //     assert_eq!(voting_power, 10_u128);
    // }

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
}
