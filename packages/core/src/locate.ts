import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function locateString() {
  const args = process.argv.slice(2);
  const queryTerm = args.join(' ').trim();

  if (!queryTerm) {
    console.log('\n❌ Error: Please provide a search term or hash pattern.');
    console.log('   Example: npm run locate 7E892875A52C59A3B588306B13C31FBD\n');
    process.exit(1);
  }

  try {
    // 1. सबसे पहले केवल आखिरी एक्टिव एसेसमेंट का कॉन्टेक्स्ट निकालें
    const latestAssessment = await prisma.assessment.findFirst({
      orderBy: { createdAt: 'desc' }
    });

    if (!latestAssessment) {
      console.error('❌ Error: No prior assessment records found in SQLite.');
      process.exit(1);
    }

    console.log('\n======================================================================');
    console.log(`🔎 [SCOPE-ISOLATED LOGIC ENGINE]: Scanning active target assets...`);
    console.log(`🎯 TARGET SCOPE : ${latestAssessment.targetUrl}`);
    console.log(`🔑 SEARCH TOKEN  : "${queryTerm}"`);
    console.log('======================================================================');

    // 2. फ़िल्टर लगाएं: केवल इस विशिष्ट एसेसमेंट आईडी के ही स्क्रिप्ट्स उठाएं
    const scripts = await prisma.script.findMany({
      where: {
        assessmentId: latestAssessment.id
      }
    });

    let matchesCount = 0;

    for (const file of scripts) {
      if (file.rawContent && file.rawContent.includes(queryTerm)) {
        matchesCount++;
        console.log(`\n✅ [MATCH #${matchesCount}] Found inside isolated target scope!`);
        console.log(`   ├── ASSET TYPE : ${file.type}`);
        console.log(`   └── SOURCE URL : ${file.url}`);
        
        const indexOfMatch = file.rawContent.indexOf(queryTerm);
        const startIdx = Math.max(0, indexOfMatch - 80);
        const endIdx = Math.min(file.rawContent.length, indexOfMatch + queryTerm.length + 80);
        const contextSnippet = file.rawContent.substring(startIdx, endIdx);
        
        console.log(`   └── CONTEXT    : ... ${contextSnippet.replace(/\s+/g, ' ').trim()} ...`);
      }
    }

    console.log('\n======================================================================');
    if (matchesCount === 0) {
      console.log(`❌ Done. Term "${queryTerm}" was not found in the active scope of: ${latestAssessment.targetUrl}`);
    } else {
      console.log(`🎉 Search Complete. Isolated target instances located: ${matchesCount}`);
    }
    console.log('======================================================================\n');

  } catch (err: any) {
    console.error(`❌ Database Query Error: ${err.message}`);
  }
}

locateString().catch(console.error);
