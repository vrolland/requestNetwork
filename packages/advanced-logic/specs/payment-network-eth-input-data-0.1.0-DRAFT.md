# Payment Network - ETH - input data

You may be interested in this document if:

- you want to create your own implementation of the Request protocol
- you are curious enough to dive and see what is under the hood of the Request protocol

Prerequisite: Having read the advanced logic specification (see [here](./advanced-logic-specs-0.1.0-DRAFT.md)).

## Description

This extension allows the payments and the refunds to be made in Ether on the Ethereum blockchain.
A payment reference has to be given in input data when making the transfer to link the payment to the request.
The payment reference is the last 8 bytes of a salted hash of the requestId: `last8Bytes(hash(requestId + salt + address))`:

- `requestId` is the id of the request
- `salt` is a random number with at least 8 bytes of randomness. It must be unique to each request
- `address` is the payment address for payments, the refund address for refunds
- `hash()` is a keccak256 hash function
- `last8Bytes()` take the last 8 bytes

As a payment network, this extension allows to deduce a payment `balance` for the request. (see
[Interpretation](#Interpretation))

## Properties

| Property                  | Type   | Description                                    | Requirement   |
| ------------------------- | ------ | ---------------------------------------------- | ------------- |
| **id**                    | String | constant value: "pn-eth-input-data"            | **Mandatory** |
| **type**                  | String | constant value: "paymentNetwork"               | **Mandatory** |
| **version**               | String | constant value: "0.1.0"                        | **Mandatory** |
| **events**                | Array  | List of the actions performed by the extension | **Mandatory** |
| **values**                | Object |                                                |               |
| **values.paymentAddress** | String | Ethereum address for the payment               | Optional      |
| **values.refundAddress**  | String | Ethereum address for the refund                | Optional      |
| **values.salt**           | String | Salt for the request                           | Optional      |

Note: to use the Rinkeby testnet just set the `currency.network` to "rinkeby"

---

## Actions

### Creation

#### Parameters

|                               | Type   | Description                         | Requirement   |
| ----------------------------- | ------ | ----------------------------------- | ------------- |
| **id**                        | String | Constant value: "pn-eth-input-data" | **Mandatory** |
| **type**                      | String | Constant value: "paymentNetwork"    | **Mandatory** |
| **version**                   | String | Constant value: "0.1.0"             | **Mandatory** |
| **parameters**                | Object |                                     |               |
| **parameters.paymentAddress** | String | Ethereum address for the payment    | Optional      |
| **parameters.refundAddress**  | String | Ethereum address for the refund     | Optional      |
| **parameters.salt**           | String | Salt for the request                | **Mandatory** |

#### Conditions

This action is valid if:

- The request `currency.type` must be "ETH"
- The request `currency.network` must be "mainnet" or 'rinkeby"
- The `salt` is not empty and long enough (8 bytes of randomness minimum).

#### Warnings

This action must trigger the warnings:

| Warning                                 | Condition                                                   |
| --------------------------------------- | ----------------------------------------------------------- |
| "paymentAddress is given by the payer"  | If `signer` is the payer **and** `paymentAddress` is given  |
| "refundAddress is given by the payee"   | If `signer` is the payee **and** `refundAddress` is given   |

Note: These warnings are necessary to highlight to avoid attempts of fake payments and refunds. For example, a payer could create a request using as the payment address one of his own addresses. A system could interpret a transaction to this address as a payment while the payee did not receive the funds.

#### Results

A extension state is created with the following properties:

|  Property                 |  Value                                                         |
| ------------------------- | -------------------------------------------------------------- |
| **id**                    | "pn-eth-input-data"                                            |
| **type**                  | "paymentNetwork"                                               |
| **version**               | "0.1.0"                                                        |
| **values**                |                                                                |
| **values.paymentAddress** | `paymentAddress` from parameters if given, undefined otherwise |
| **values.refundAddress**  | `refundAddress` from parameters if given, undefined otherwise  |
| **values.salt**           | Salt for the request                                           |
| **events**                | Array with one 'create' event (see below)                      |

the 'create' event:

|  Property                     |  Value                                                         |
| ----------------------------- | -------------------------------------------------------------- |
| **name**                      | 'create'                                                       |
| **parameters**                |                                                                |
| **parameters.paymentAddress** | `paymentAddress` from parameters if given, undefined otherwise |
| **parameters.refundAddress**  | `refundAddress` from parameters if given, undefined otherwise  |
| **parameters.salt**           | Salt for the request                                           |

---

### Updates

#### addPaymentAddress

##### Parameters

|                               | Type   | Description                         | Requirement   |
| ----------------------------- | ------ | ----------------------------------- | ------------- |
| **id**                        | String | Constant value: "pn-eth-input-data" | **Mandatory** |
| **action**                    | String | Constant value: "addPaymentAddress" | **Mandatory** |
| **parameters**                | Object |                                     |               |
| **parameters.paymentAddress** | String | Ethereum address for the payment    | **Mandatory** |

##### Conditions

This action is valid, if:

- The extension state with the id "pn-eth-input-data" exists
- The signer is the `payee`
- The extension property `paymentAddress` is undefined

##### Warnings

None.

##### Results

A extension state is updated with the following properties:

|  Property                  |  Value                                               |
| -------------------------- | ---------------------------------------------------- |
| **values.paymentAddress**  | `paymentAddress` from parameters                     |
| **parameters.paymentSalt** | Salt for the payment                                 |
| **events**                 | Add an 'paymentAddress' event (see below) at its end |

the 'addPaymentAddress' event:

|  Property                     |  Value                              |
| ----------------------------- | ----------------------------------- |
| **name**                      | Constant value: "addPaymentAddress" |
| **parameters**                |                                     |
| **parameters.paymentAddress** | `paymentAddress` from parameters    |

#### addRefundAddress

##### Parameters

|                              | Type   | Description                         | Requirement   |
| ---------------------------- | ------ | ----------------------------------- | ------------- |
| **id**                       | String | Constant value: "pn-eth-input-data" | **Mandatory** |
| **action**                   | String | Constant value: "addRefundAddress"  | **Mandatory** |
| **parameters**               | Object |                                     |               |
| **parameters.refundAddress** | String | Ethereum address for the refund     | **Mandatory** |

##### Conditions

This action is valid if:

- The extension state with the id "pn-eth-input-data" exists
- The signer is the `payer`
- The extension property `refundAddress` is undefined

##### Warnings

None.

##### Results

A extension state is updated with the following properties:

|  Property                |  Value                                                 |
| ------------------------ | ------------------------------------------------------ |
| **values.refundAddress** | `refundAddress` from parameters                        |
| **values.refundSalt**    | Salt for the refund                                    |
| **events**               | Add an 'addRefundAddress' event (see below) at its end |

The 'addRefundAddress' event:

|  Property                    |  Value                          |
| ---------------------------- | ------------------------------- |
| **name**                     | 'addRefundAddress'              |
| **parameters**               |                                 |
| **parameters.refundAddress** | `refundAddress` from parameters |

---

## Interpretation

The `balance` starts from `0`.
Any ETH transaction to `paymentAddress` with exactly `last8Bytes(hash(requestId + salt + payment address))` in input data is considered as a payment. The `balance` is increased by the sum of the amounts of the transactions.
Any ETH transaction to `refundAddress` with exactly `last8Bytes(hash(requestId + salt + refund address))` in input data is considered as a refund. The `balance` is reduced by the sum of the amounts of the transactions.
