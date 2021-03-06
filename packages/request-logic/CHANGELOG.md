# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

## [0.8.1](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.8.0...@requestnetwork/request-logic@0.8.1) (2019-12-04)


### Bug Fixes

* rollback legacy request currency renaming from DAI to SAI ([#622](https://github.com/RequestNetwork/requestNetwork/issues/622)) ([2882811](https://github.com/RequestNetwork/requestNetwork/commit/28828117f6490ada05180f2607098d3ebada681a))





# [0.8.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.7.1...@requestnetwork/request-logic@0.8.0) (2019-11-20)


### Bug Fixes

* throw when no encryption parameters is given to create an encrypted request ([#593](https://github.com/RequestNetwork/requestNetwork/issues/593)) ([d18a894](https://github.com/RequestNetwork/requestNetwork/commit/d18a8946085920f13a43e269814fba857f24039a))


### Features

* add ERC20 currency list ([#584](https://github.com/RequestNetwork/requestNetwork/issues/584)) ([6e0ed87](https://github.com/RequestNetwork/requestNetwork/commit/6e0ed8758ffd5edcd9a498028c2b6873c26d49ca))
* translate currency string to object ([#581](https://github.com/RequestNetwork/requestNetwork/issues/581)) ([b220d20](https://github.com/RequestNetwork/requestNetwork/commit/b220d20ae1866e8db076718989726334b91c0f44))
* validate role for increase & decrease ([#590](https://github.com/RequestNetwork/requestNetwork/issues/590)) ([4793782](https://github.com/RequestNetwork/requestNetwork/commit/47937828a0f42e912eda440be4e277f26aa51bdb))
* Validation of accept, cancel and add extension data ([#599](https://github.com/RequestNetwork/requestNetwork/issues/599)) ([8f7798e](https://github.com/RequestNetwork/requestNetwork/commit/8f7798e6e71819e5201efaf73678ff5b71b52503))
* **request-logic:** check advanced logic when creating a request ([#607](https://github.com/RequestNetwork/requestNetwork/issues/607)) ([352d2a3](https://github.com/RequestNetwork/requestNetwork/commit/352d2a3ca90a57ad43e55737d2111b6da5137e75))





## [0.7.1](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.7.0...@requestnetwork/request-logic@0.7.1) (2019-10-21)

**Note:** Version bump only for package @requestnetwork/request-logic






# [0.7.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.6.0...@requestnetwork/request-logic@0.7.0) (2019-09-16)


### Features

* **transaction-manager:** add transaction to an existing encrypted channel ([#524](https://github.com/RequestNetwork/requestNetwork/issues/524)) ([027a0f5](https://github.com/RequestNetwork/requestNetwork/commit/027a0f5))
* get requests by multiple topics or multiple identities ([#530](https://github.com/RequestNetwork/requestNetwork/issues/530)) ([8fe7d30](https://github.com/RequestNetwork/requestNetwork/commit/8fe7d30))





# [0.6.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.5.0...@requestnetwork/request-logic@0.6.0) (2019-09-05)


### Features

* request logic version 2.0.1: compute the request id takes in account the signature ([#511](https://github.com/RequestNetwork/requestNetwork/issues/511)) ([14643d8](https://github.com/RequestNetwork/requestNetwork/commit/14643d8))
* Transaction-manager: ignore the wrong transactions of channels ([#514](https://github.com/RequestNetwork/requestNetwork/issues/514)) ([4ec82c6](https://github.com/RequestNetwork/requestNetwork/commit/4ec82c6))
* **transaction-manager:** decrypt channels  ([#516](https://github.com/RequestNetwork/requestNetwork/issues/516)) ([8142c3d](https://github.com/RequestNetwork/requestNetwork/commit/8142c3d))
* **transaction-manager:** get encrypted channels by topic ([#519](https://github.com/RequestNetwork/requestNetwork/issues/519)) ([5f4a77e](https://github.com/RequestNetwork/requestNetwork/commit/5f4a77e))






# [0.5.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.4.0...@requestnetwork/request-logic@0.5.0) (2019-08-19)


### Features

* Request logic: create encrypted request ([#496](https://github.com/RequestNetwork/requestNetwork/issues/496)) ([9f1ebe6](https://github.com/RequestNetwork/requestNetwork/commit/9f1ebe6))






# [0.3.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.3.0) (2019-07-24)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* add the reason when ignoring a transactions ([#408](https://github.com/RequestNetwork/requestNetwork/issues/408)) ([8697a6e](https://github.com/RequestNetwork/requestNetwork/commit/8697a6e))
* compute the requestId before creation with computeRequestId ([#407](https://github.com/RequestNetwork/requestNetwork/issues/407)) ([c88c6f6](https://github.com/RequestNetwork/requestNetwork/commit/c88c6f6))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))





## [0.2.1-alpha.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.2.1-alpha.0) (2019-07-22)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* add the reason when ignoring a transactions ([#408](https://github.com/RequestNetwork/requestNetwork/issues/408)) ([8697a6e](https://github.com/RequestNetwork/requestNetwork/commit/8697a6e))
* compute the requestId before creation with computeRequestId ([#407](https://github.com/RequestNetwork/requestNetwork/issues/407)) ([c88c6f6](https://github.com/RequestNetwork/requestNetwork/commit/c88c6f6))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))





# [0.2.0](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.2.0) (2019-06-06)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* add the reason when ignoring a transactions ([#408](https://github.com/RequestNetwork/requestNetwork/issues/408)) ([8697a6e](https://github.com/RequestNetwork/requestNetwork/commit/8697a6e))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))






## [0.1.1-alpha.12](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.1.1-alpha.12) (2019-05-21)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))






## [0.1.1-alpha.11](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.1.1-alpha.11) (2019-05-17)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))






## [0.1.1-alpha.10](https://github.com/RequestNetwork/requestNetwork/compare/@requestnetwork/request-logic@0.1.1-alpha.4...@requestnetwork/request-logic@0.1.1-alpha.10) (2019-05-10)


### Features

* add getChannelByTopic in data-access ([#305](https://github.com/RequestNetwork/requestNetwork/issues/305)) ([b345df8](https://github.com/RequestNetwork/requestNetwork/commit/b345df8))
* getRequestsByIdentity include timestamp boundaries in request-clients ([#308](https://github.com/RequestNetwork/requestNetwork/issues/308)) ([1fd2df5](https://github.com/RequestNetwork/requestNetwork/commit/1fd2df5))
* introduce channelIds to enhance the topics mechanism ([#297](https://github.com/RequestNetwork/requestNetwork/issues/297)) ([6072905](https://github.com/RequestNetwork/requestNetwork/commit/6072905))
* payment network declarative for any currency ([#315](https://github.com/RequestNetwork/requestNetwork/issues/315)) ([06fb561](https://github.com/RequestNetwork/requestNetwork/commit/06fb561))
* Timestamp from storage to client ([#309](https://github.com/RequestNetwork/requestNetwork/issues/309)) ([bb0ac19](https://github.com/RequestNetwork/requestNetwork/commit/bb0ac19))
