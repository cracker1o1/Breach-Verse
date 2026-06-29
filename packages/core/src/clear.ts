import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function clearDatabase() {
  console.log('\n======================================================================');
  console.log('🧹 DATABASE HOUSE-CLEANING ENGINE ACTIVATED');
  console.log('======================================================================');
  console.log('[*] Purging all historical assessment logs, endpoints, and scripts...');

  try {
    // रिलेशनल ऑर्डर में डेटा डिलीट करें ताकि फॉरेन की एरर न आए
    const deletedFindings = await prisma.assessment.deleteMany({});
    const deletedEndpoints = await prisma.endpoint.deleteMany({});
    const deletedScripts = await prisma.script.deleteMany({});
    const deletedAssessments = await prisma.assessment.deleteMany({});

    console.log('✅ Purge completed successfully!');
    console.log(`   ├── Removed ${deletedAssessments.count} historical targets.`);
    console.log(`   ├── Cleared ${deletedScripts.count} saved JS/JSON assets.`);
    console.log(`   ├── Flushed ${deletedEndpoints.count} extracted network endpoints.`);
    console.log(`   └── Dropped ${deletedFindings.count} vulnerability alerts.`);
    console.log('======================================================================\n');
  } catch (err: any) {
    console.error(`❌ Failed to clear database storage layer: ${err.message}`);
  }
}

clearDatabase().catch(console.error);
