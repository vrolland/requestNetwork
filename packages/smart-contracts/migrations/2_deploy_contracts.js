const ERC20FeeProxy = artifacts.require('ERC20FeeProxy');

module.exports = async function (deployer) {
  await deployer.deploy(ERC20FeeProxy);
};
