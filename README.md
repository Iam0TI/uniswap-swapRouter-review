# uniswap-swapRouter-review
| Topic          | UniswapV3 SwapRouter.sol            |
| :------------- | :-----------------------------------|
| Title          | Smart Contract Review               |
| Author         | [Iam0TI](https://github.com/Iam0TI) |                                          |
| Date Created   |Novebemer 4, 2024                    |


![the graph diagram of [SwapRouter.sol](https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol)](<Pasted image 20241104102610.png>)
> the graph diagram of [SwapRouter.sol](https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol)
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




