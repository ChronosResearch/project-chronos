const hre = require("hardhat");

async function main() {
  console.log("Starting deployment of Chronos Protocol to Testnet...");

  // 1. Deploy the ZK-SNARK Verifier
  console.log("Deploying ChronosVerifier...");
  const verifier = await hre.ethers.deployContract("ChronosVerifier");
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log(`✅ ChronosVerifier deployed to: ${verifierAddress}`);

  // 2. Deploy the Staking and Slashing Contract
  console.log("Deploying ChronosStaking...");
  const staking = await hre.ethers.deployContract("ChronosStaking", [verifierAddress]);
  await staking.waitForDeployment();
  const stakingAddress = await staking.getAddress();
  console.log(`✅ ChronosStaking deployed to: ${stakingAddress}`);

  console.log("\nDeployment Complete! 🎉");
  console.log("-----------------------------------------");
  console.log(`Verifier: ${verifierAddress}`);
  console.log(`Staking:  ${stakingAddress}`);
  console.log("-----------------------------------------");
  console.log("Save these addresses in your frontend configuration.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
