# uniswap-swapRouter-review
| Topic          | UniswapV3 SwapRouter.sol            |
| :------------- | :-----------------------------------|
| Title          | Smart Contract Review               |
| Author         | [Iam0TI](https://github.com/Iam0TI) |                                          |
| Date Created   |Novebemer 4, 2024                    |


![the graph diagram of [SwapRouter.sol](https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol)](<Pasted image 20241104102610.png>)
> the graph diagram of [SwapRouter.sol](https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol)



## Overview

The `SwapRouter.sol` contract in Uniswap V3 is a central piece of the Uniswap ecosystem, it is used managing the token swap functionality.   It allows user to perform both single-token swaps and chained, multihop swaps across the uniswap V3 pools. This review delves into the core functionalities, libraries  and  system design within `SwapRouter.sol`. `SwapRouter.sol` uses Uniswap V3’s unique features, like [concentrated liquidity](https://docs.uniswap.org/concepts/protocol/concentrated-liquidity) and customizable fee . This review shows how this feature are used . 

The contract inherits from the following contracts, each giving the swapRouter a specific functionalities:

- **ISwapRouter**: Defines the core interface for swap operations, setting the functions required for both single- and multi-hop swaps.
- **PeripheryImmutableState**: Manages immutable state variables like the factory and WETH9 addresses.
- **PeripheryValidation**: Contains modifer `checkDeadline` to check if the deadline of a trade as passed.
- **PeripheryPaymentsWithFee** :  Contians functions to ease deposits and withdrawals of ETH  within the router.
- **Multicall** (Not used): Allows multiple function calls to be batched in a single transaction.
- **SelfPermit** (Not used): Implements EIP-2612 permits, allowing users to approve token allowances with signatures, reducing the need for separate approval transactions.


|File to Review | SLOC |
| :-------- | :------- |
| Contracts: 1 | |
| `SwapRouter.sol` | `214` |
| | |
| Import Path                                                    | Description                                                                                         |
|----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `@uniswap/v3-core/contracts/libraries/SafeCast.sol`            | Provides safe casting functions for different data types, ensuring values fit within specified limits. |
| `@uniswap/v3-core/contracts/libraries/TickMath.sol`            | Contains mathematical functions for calculating tick prices, used for Uniswap V3 pool operations.   |
| `@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol`     | Interface for interacting with Uniswap V3 pools, facilitating swaps and liquidity management.       |
| `./interfaces/ISwapRouter.sol`                                 | Interface defining the functions of the Swap Router contract.                                       |
| `./base/PeripheryImmutableState.sol`                           | Contains immutable state variables like factory and WETH9 addresses.                                |
| `./base/PeripheryValidation.sol`                               | Handles time validation checks for swap router functions.                                                |
| `./base/PeripheryPaymentsWithFee.sol`                          | Manages payment transfers with additional fee-handling logic.                                       |
| `./libraries/Path.sol`                                         | Utility library for handling encoded swap paths.                                                    |
| `./libraries/PoolAddress.sol`                                  | Provides functions for computing pool addresses based on token pairs and fees.                      |
| `./libraries/CallbackValidation.sol`                           | Validates callback requests to ensure they originate from a valid Uniswap V3 pool.                  |
| `./base/Multicall.sol`                                         | Enables batch execution of multiple function calls within a single transaction.                     |
| `./base/SelfPermit.sol`                                        | Allows users to permit token transfers through EIP-2612 signatures, reducing the need for approvals.|
| `./interfaces/external/IWETH9.sol`                             | Interface for interacting with WETH9, wrapping and unwrapping ETH to/from WETH.                     |


Before delving in the main `SwapRouter` contract we need to understand some Libaries because they are important to the in working of the contract.

### Libraries Overview

#### 1. `Path.sol`

The **`Path`** library contains functions for manipulating path data for multihop swaps . Each path contains a list of token addresses and the fees associated with each token pool,. This encoding is used to set up  swaping routes in Uniswap v3, allowing users to swap multiple token pairs one after another through connected pools.

##### Constant Definitions

```solidity
uint256 private constant ADDR_SIZE = 20; // token address length in bytes
uint256 private constant FEE_SIZE = 3;   // pool fee length in bytes
uint256 private constant NEXT_OFFSET = ADDR_SIZE + FEE_SIZE;  // 23 bytes, total length for token + fee
uint256 private constant POP_OFFSET = NEXT_OFFSET + ADDR_SIZE; // 43 bytes, full pool segment length
uint256 private constant MULTIPLE_POOLS_MIN_LENGTH = POP_OFFSET + NEXT_OFFSET; // 66 bytes, min length for multi-pool path
```

Each constant represents:
- **`ADDR_SIZE`**: The byte length of the encoded token address (20 bytes).
- **`FEE_SIZE`**: The byte length of the encoded fee value for a pool (3 bytes). 
- **`NEXT_OFFSET`**: The byte length for a single token address and fee together (23 bytes). This means that each "pool" section (or "hop" in a multi-hop swap) occupies `20 + 3 = 23` bytes.

- **`POP_OFFSET`**: Total byte length(offset) for a pool , including two token addresses and a fee value (`TokenA` → `TokenB` → + `fee`)(43 bytes).
- **`MULTIPLE_POOLS_MIN_LENGTH`**: Minimum byte length of a path with two or more pools (66 bytes). Consider a multihop path from `TokenA` → `TokenB` → `TokenC` with fees of `0.3%` and `0.05%`  i.e  three token addresses (60 bytes), two fees (6 bytes).

##### Functions

##### 1. `hasMultiplePools`

```solidity
function hasMultiplePools(bytes memory path) internal pure returns (bool) {
    return path.length >= MULTIPLE_POOLS_MIN_LENGTH;
}
```

**Purpose**: To checks if the `path` has multiple pools (i.e., it involves multiple tokens and fees).
- **Parameters**: `path` - the bytes encoded swap path.
- **Returns**: `true` if the `path` length is equal to or more the `MULTIPLE_POOLS_MIN_LENGTH` (66 bytes), indicating two or more pools.

##### 2. `numPools`

```solidity
function numPools(bytes memory path) internal pure returns (uint256) {
    return ((path.length - ADDR_SIZE) / NEXT_OFFSET);
}
```

**Purpose**: to calculates the number of pools in the given path.
- **Parameters**: `path` - the bytes encoded swap path.
- **Returns**: The number of pools, calculated by taking the length of the path, subtracting the initial token address size, and dividing by the combined size of each token-fee pair (`NEXT_OFFSET`).
 - **Explanation** of `numPools` Calculation 

```solidity

Suppose we have a path with two pools:

Pool 1 :Token A → Fee → Token B
Pool 2 :Token B → Fee → Token C

In bytes, this would look like:

[Token A (20 bytes)] + [Fee (3 bytes)] + [Token B (20 bytes)] + [Fee (3 bytes)] + [Token C (20 bytes)] = 66 bytes 

Calculations in numPools

 We subtract 20 bytes from the total length to account for the initial token, leaving 66 - 20 = 46 bytes.
 
Dividing by NEXT_OFFSET (23) gives 46 / 23 = 2, indicating two pools in the path.

So, numPools will return 2 , representing two pools in the path.

```

##### 3. `decodeFirstPool`

```solidity
function decodeFirstPool(bytes memory path)
    internal
    pure
    returns (
        address tokenA,
        address tokenB,
        uint24 fee
    )
{
    tokenA = path.toAddress(0);                // tokenA address
    fee = path.toUint24(ADDR_SIZE);            // 3-byte fee following tokenA
    tokenB = path.toAddress(NEXT_OFFSET);      // tokenB address after fee
}
```

**Purpose**:To decode the first pool in the path, extracting the token addresses and fee.
- **Parameters**: `path` - the bytes encoded swap path.
- **Returns**: `tokenA` (first token address), `fee` (3-byte pool fee), `tokenB` (second token address).
- **Explanation**:
  - uses `path.toAddress(0)` to get the address of `tokenA`. 
  - extracts the fee using `path.toUint24(ADDR_SIZE)` at a 20-byte offset (after `tokenA`).
  -  uses `path.toAddress(NEXT_OFFSET)`  to get the `tokenB` address at `NEXT_OFFSET`, which is 23 bytes from the start (20 bytes for `tokenA` + 3 bytes for the fee).
> the `toAddress(bytes memory _bytes, uint256 _start)` function converts a  portion of the byte array into an  address, which is 20 bytes long. The `_start` parameter indicate the starting offset in the bytes for where to start reading the address. Similar, the `toUint24(bytes memory _bytes, uint256 _start)` function converts a 3-byte portion  of the byte array into a 24-bit unsigned integer. Similar to `toAddress`, the `_start` parameter indicate where in the byte array the conversion begins. This to function are from the BytesLib.sol

##### 4. `getFirstPool`

```solidity
function getFirstPool(bytes memory path) internal pure returns (bytes memory) {
    return path.slice(0, POP_OFFSET);
}
```

**Purpose**: To extracts the first pool portion in the path.
- **Parameters**: `path` - the bytes encoded swap path.
- **Returns**: A byte slice containing the first pool portion.
- **Explanation**: Uses `path.slice(0, POP_OFFSET)` to capture the portion from the start through `POP_OFFSET` (first two tokens and the fee).
> the `slice` function is also  from BytesLib.sol

##### 5. `skipToken`

```solidity
function skipToken(bytes memory path) internal pure returns (bytes memory) {
    return path.slice(NEXT_OFFSET, path.length - NEXT_OFFSET);
}
```

**Purpose**: To skips  token and fee portion, returning the remainder of the path.
- **Parameters**: `path` - the bytes encoded swap path.
- **Returns**: Remaining bytes after skipping the first token-fee portion.
- **Explanation**: `path.slice(NEXT_OFFSET, path.length - NEXT_OFFSET)` omits the first `NEXT_OFFSET` bytes (token + fee) from the path, returning what remains after this initial portion. 

###### Practical Example

Let’s look at a multihop path from `TokenA` → `TokenB` → `TokenC` with fees of `0.3%` and `0.05%`:
1. Path Encoding: `TokenA` (20 bytes) + `0.3%` (3 bytes) + `TokenB` (20 bytes) + `0.05%` (3 bytes) + `TokenC` (20 bytes) = 66 bytes.
2. **`hasMultiplePools`**: This function would return `true` since the path length (66 bytes) is at least `MULTIPLE_POOLS_MIN_LENGTH`.
3. **`numPools`**: This function would return 2, indicating two pools in the path.
4. **`decodeFirstPool`**: Returns `TokenA`, `TokenB`, and `0.3%`.
5. **`getFirstPool`**: Returns the first 43 bytes, enough to contain `TokenA`, `TokenB`, and `0.3%`.
6. **`skipToken`**: Skips `TokenA` and `0.3%`, returning the remaining path for `TokenB` → `TokenC` with `0.05%` fee.


#### 2. `PoolAddress.sol`


The **`PoolAddress`** library provides functions to get the address of a Uniswap V3 pool based on its factory,the pair tokens, and the fee.

##### Constants
 **`POOL_INIT_CODE_HASH`**: A constant that represents the initi code hash for Uniswap V3 pools. This value is used in computing the pool address. we will see why the is needed in a bit.

##### Struct
The `PoolKey` struct represents the  structure a pool and includes the addresses of the first and second tokens in the pool (sorted as `token0` and `token1`, respectively) along with the  pool fee.

##### Functions

##### 1.`getPoolKey`

```solidity
function getPoolKey(
address tokenA,
address tokenB,
uint24 fee
) internal pure returns (PoolKey memory) {
if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);
return PoolKey({token0: tokenA, token1: tokenB, fee: fee});
}
```

- **Purpose** : To  ordered tokens addresses and returns a `PoolKey` that includes the ordered tokens and the pool fee.
- **Parameters**:
    - `tokenA`: The first token of a pool.
    - `tokenB`: The second token of a pool. 
    - `fee`: The fee level of the pool.
- **Returns**: A `PoolKey` struct that contains the ordered `token0` and `token1` assignments, ensuring `token0` is always less than `token1`.

**Explanation**: The function checks if `tokenA` is greater than `tokenB` and swaps them if necessary to maintain the order. It then creates and returns a `PoolKey` with the ordered tokens and the fee.

##### 2. `computeAddress`

``` solidity
function computeAddress(address factory, PoolKey memory key) internal pure returns (address pool) {
require(key.token0 < key.token1);
pool = address(uint256(keccak256(abi.encodePacked(hex'ff',factory,keccak256(abi.encode(key.token0, key.token1, key.fee)),POOL_INIT_CODE_HASH))));}
```


- **Purpose**: To computes the address of a pool deterministically given the factory address and the PoolKey.
- **Parameters**:
    - `factory`: The address of the Uniswap V3 factory contract.
    - `key`: The PoolKey containing the tokens and fee.
- **Returns**: The contract address of the V3 pool.

**Explanation**: The function requires that token0 is less than token1. It then computes the pool's address using the provided factory address, the hash of the tokens and fee, and the POOL_INIT_CODE_HASH. [Just like how new contract are deployer using Create2](https://eips.ethereum.org/EIPS/eip-1014). The result is a deterministic pool address of the pairs.




#### 3. `CallbackValidation.sol`

The **`CallbackValidation`** library contains functions to validate callbacks from Uniswap V3 Pools. It ensures that the callbacks made to the pool are from valid and authorized addresses, helping to prevent unauthorized interactions with the pool contracts.

##### Function
##### 1. `verifyCallback` 

```solidity
function verifyCallback(address factory, PoolAddress.PoolKey memory poolKey)
internal view returns (IUniswapV3Pool pool)
{
pool = IUniswapV3Pool(PoolAddress.computeAddress(factory, poolKey));
    require(msg.sender == address(pool));
}
```

- **Purpose**: To verify if the sender of the callback is the expected  Uniswap  V3 pool.
- **Parameters**:
        `factory`: The contract address of the Uniswap V3 factory.
        `poolKey`: The identifying key of the V3 pool that includes the token addresses and the fee.
- **Returns**:  `pool` : A uniswap v3 pool contract address.
- **Explanation**:The function calls `PoolAddress.computeAddress(..)`  to compute the pool after that it checks that the sender of the callback (msg.sender) is indeed the computed pool address. If the sender is not the expected pool address, the transaction will revert.
##### 2. `verifyCallback`

```solidity
function verifyCallback(
    address factory,
    address tokenA,
    address tokenB,
    uint24 fee
) internal view returns (IUniswapV3Pool pool) {
    return verifyCallback(factory, PoolAddress.getPoolKey(tokenA, tokenB, fee));
}
```

**Purpose**: To verify if the sender of the callback is the expected  Uniswap  V3 pool.

- **Parameters**:
    - `factory`: The contract address of the Uniswap V3 factory.
    - `tokenA`: The contract address of either token0 or token1 in the pool.
    - `tokenB`: The contract address of the other token in the pool.
    - `fee`: The pool
- **Returns**:  `pool` : A uniswap v3 pool contract address.
- **Explanation** : The function makes a call to `PoolAddress.getPoolKey()` which return a `Poolkey` and `factorty` are passed as parameter to the first `verifyCallback` function and that Verification and computation of the pool address happens. 



### Contract Review 

Now Let's delving into the inner workings of the coNtract .



#### State Variable and Library Usage

```solidity 
    using Path for bytes;
    using SafeCast for uint256;

    /// @dev Used as the placeholder value for amountInCached, because the computed amount in for an exact output swap
    /// can never actually be this value
    uint256 private constant DEFAULT_AMOUNT_IN_CACHED = type(uint256).max;

    /// @dev Transient storage variable used for returning the computed amount in for an exact output swap.
    uint256 private amountInCached = DEFAULT_AMOUNT_IN_CACHED;


```

1. **Library Usage**
   - `using Path for bytes;`: This line allows the contract to extend the functionality of the `bytes` type with the `Path` library in `Path.sol`. It is used for handling paths during token swaps by decoding the route of token transfers.

   - `using SafeCast for uint256;`: This line enables the use of the `SafeCast` library on the `uint256` type. Since we are using `solidity version 0.7.6;` , `SafeCast` provides safe way for casting between different integer types, which helps prevent overflow and underflow errors .

2. **State Variables**
   - `uint256 private constant DEFAULT_AMOUNT_IN_CACHED = type(uint256).max;`: This constant defines a placeholder value for `amountInCached`. It is set to the maximum value of `uint256`, indicating that this value is used when the actual amount in for an exact output swap is not yet computed.
   - `uint256 private amountInCached = DEFAULT_AMOUNT_IN_CACHED;`: This transient storage variable holds the computed amount in for an exact output swap. It is initialized with the `DEFAULT_AMOUNT_IN_CACHED` value, signaling that the actual amount has yet to be determined.

These components work together to ensure efficient management of swap calculations and maintain safety in type conversions within the `SwapRouter` contract.

#### Fucntions 

##### 1. Constructor

```solidity 
constructor(address _factory, address _WETH9) PeripheryImmutableState(_factory, _WETH9) {}

```

**Purpose**: To sets up the contract initial state variable in `PeripheryImmutableState`.


- **Parameters**:
  - `address _factory`: The address of the Uniswap V3 factory contract, which is responsible for creating new liquidity pools.
  - `address _WETH9`: The address of the Wrapped Ether (WETH) contract.It the router to handle ETH by wrapping it as WETH for token swaps.

- **Inheritance**: 
  - `PeripheryImmutableState(_factory, _WETH9)`: The constructor of the `PeripheryImmutableState` base contract is called with `_factory` and `_WETH9` as arguments. 

- **Explanation**:  


###### 2. `getPool`

```solidity
function getPool(address tokenA, address tokenB, uint24 fee) private view returns (IUniswapV3Pool) {
    return IUniswapV3Pool(PoolAddress.computeAddress(factory, PoolAddress.getPoolKey(tokenA, tokenB, fee)));
}
```

**Purpose**:  
The `getPool` function gets the Uniswap V3 pool contract address for a specified token pair . It used the `PoolAddress` library to compute the pool address based on the factory contract, token addresses, and fee. 

**Parameters**:  
- `tokenA`: The address of the first token in the pool.
- `tokenB`: The address of the second token in the pool.
- `fee`: The fee tier of the pool, represented as a 24-bit unsigned integer.

**Returns**:  
- `IUniswapV3Pool`: A Uniswap V3 pool contract address for the specified token pair and fee.

**Explanation**:
1. **Pool Key Ordering**:  
   Using `PoolAddress.getPoolKey(tokenA, tokenB, fee)` to generate a unique, ordered key for the token pair and fee. This ensures the token order is consistent for pool address computation.

2. **Compute Pool Address**:  
   Using `PoolAddress.computeAddress(factory, poolKey)` to get the pool’s address based on the `CREATE2` formula used during pool deployment. 

3. **Type Casting**:  
   Casts the computed address to `IUniswapV3Pool` to enable interaction with the Uniswap V3 pool's functions.

**Libraries Used**:
- `PoolAddress`:  
    - `getPoolKey`: Generates a unique, ordered identifier for the token pair and fee to maintain consistency.
    - `computeAddress`: Computes a pool's address based on the factory address and pool key.
  

##### 3. `uniswapV3SwapCallback`
```solidity

struct SwapCallbackData {
        bytes path;
        address payer;
    }

    /// @inheritdoc IUniswapV3SwapCallback
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata _data
    ) external override {
        require(amount0Delta > 0 || amount1Delta > 0); // swaps entirely within 0-liquidity regions are not supported
        SwapCallbackData memory data = abi.decode(_data, (SwapCallbackData));
        (address tokenIn, address tokenOut, uint24 fee) = data.path.decodeFirstPool();
        CallbackValidation.verifyCallback(factory, tokenIn, tokenOut, fee);

        (bool isExactInput, uint256 amountToPay) =
            amount0Delta > 0
                ? (tokenIn < tokenOut, uint256(amount0Delta))
                : (tokenOut < tokenIn, uint256(amount1Delta));
        if (isExactInput) {
            pay(tokenIn, data.payer, msg.sender, amountToPay);
        } else {
            // either initiate the next swap or pay
            if (data.path.hasMultiplePools()) {
                data.path = data.path.skipToken();
                exactOutputInternal(amountToPay, msg.sender, 0, data);
            } else {
                amountInCached = amountToPay;
                tokenIn = tokenOut; // swap in/out because exact output swaps are reversed
                pay(tokenIn, data.payer, msg.sender, amountToPay);
            }
        }
    }
```

**Purpose**:  
The `uniswapV3SwapCallback` function handles the callback required during a Uniswap v3 swap. It check the swap if valid and handles payments depending on whether it is an exact input or exact output swap. For exact output swaps, either initiate the next swap  or pay if it's the last pool.

**Parameters**:
- `amount0Delta`: `int256` - The change in amount of token0 as a result of the swap.
- `amount1Delta`: `int256` - The change in amount of token1 as a result of the swap.
- `_data`: `bytes calldata` - Encoded data for the swap callback, containing the path and payer address.

**Returns**:  
None. This is a callback functions.

**Explanation**:  
- The function first checks that either `amount0Delta` or `amount1Delta` is positive, ensuring there’s liquidity in the swap region (remember concentrated liquidity ).
- It decodes `_data` into a `SwapCallbackData` struct, extracting the path, token addresses, and fee.
- Using `CallbackValidation.verifyCallback`, it verifies that the callback is valid by checking the factory, `tokenIn`, `tokenOut`, and fee i.e the call is from a uniswap v3 pool.
- Depending on the delta values, it determines whether the swap is an exact input or exact output and sets `amountToPay` to the respective delta amount.
    **For :**
  - **Exact Input Swap**: If it's an exact input swap (`isExactInput` is true), the function calls `pay` (inherited from   `PeripheryPayments`) to transfer `amountToPay` from `data.payer` to `msg.sender` for `tokenIn`.
  
  - **Exact Output Swap**: If it's an exact output swap, the function checks if the `path` has more pools:
    - If **more pools** exist, it skips the current token and initiates the next swap using `exactOutputInternal`.
    - If **no more pools** are in the path, it caches `amountToPay` in `amountInCached` and swaps the token directions (in/out). Finally, it calls `pay` to complete the payment.

**Libraries Used**:  
- `CallbackValidation`: Used to validate the swap callback.
- `Path`: Provides methods like `decodeFirstPool` and `skipToken` to handle path decoding and token skipping for multi-pool swaps.



##### 4. `exactInputInternal`


```solidity
function exactInputInternal(
    uint256 amountIn,
    address recipient,
    uint160 sqrtPriceLimitX96,
    SwapCallbackData memory data
) private returns (uint256 amountOut) {
    // allow swapping to the router address with address 0
    if (recipient == address(0)) recipient = address(this);

    (address tokenIn, address tokenOut, uint24 fee) = data.path.decodeFirstPool();

    bool zeroForOne = tokenIn < tokenOut;

    (int256 amount0, int256 amount1) =
        getPool(tokenIn, tokenOut, fee).swap(
            recipient,
            zeroForOne,
            amountIn.toInt256(),
            sqrtPriceLimitX96 == 0
                ? (zeroForOne ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1)
                : sqrtPriceLimitX96,
            abi.encode(data)
        );

    return uint256(-(zeroForOne ? amount1 : amount0));
}

```

**Purpose**:  
This function performs a single exact input swap in the Uniswap V3 protocol, allowing users to exchange a specified amount of one token for another.

**Parameters**:  
- `uint256 amountIn`: The amount of the input token to be swapped.  
- `address recipient`: The address that will receive the output tokens. If this is set to the zero address, it is replaced with the router's address.  
- `uint160 sqrtPriceLimitX96`: The square root price limit for the swap, specified in fixed-point Q96 format. If this is zero, it uses a calculated boundary value based on the swap direction.  
- `SwapCallbackData memory data`: A structure that contains additional information for the swap, including the token path and fee.  

**Returns**:  
- `uint256 amountOut`: The amount of the output token received from the swap.


**Explanation**:  
The function first checks if the `recipient` is the zero address. If so, it sets the recipient to the contract's address, allowing swaps to be conducted directly to the router. It then decodes the path from the `data` structure to obtain the `tokenIn`, `tokenOut`, and fee for the swap. 

Next, it determines the direction of the swap (`zeroForOne`) by checking if the address `tokenIn` is less than `tokenOut`.Then the `getPool` function is called to retrieve the right liquidity pool for the swap, and the `swap` method is called on the returned pool to be perform the swap . The  swap parameters include:

- `recipient`: The address receiving the output tokens.
- `zeroForOne`: A boolean indicating the swap direction.
- `amountIn`: The input amount converted to an integer.
- `sqrtPriceLimitX96`: The function checks if whether price limit  was provided if not it uses the tick boundary value from the `TickMath` libary depending on the swap direction. If the swap is from `tokenIn` to `tokenOut` `zeroForOne` is true so `sqrtPriceLimitX96` is  `TickMath.MIN_SQRT_RATIO + 1`  else `sqrtPriceLimitX96` is ` TickMath.MAX_SQRT_RATIO -1 `
- `data`: The encoded callback data.

Finally, it calculates and returns the output amount by converting the negative value of the amount withdrawn from the pool, based on the swap direction.


**Libraries Used**:  
- `Path`: For decoding the token path.  
- `SafeCast`: For safely casting between integer types.
- `TickMath`: To determine the value of `sqrtPriceLimitX96`



