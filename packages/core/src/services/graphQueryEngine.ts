import { PrismaClient } from '@prisma/client';

export class GraphQueryEngine {
  private prisma: PrismaClient;
  constructor(prismaInstance: PrismaClient) { this.prisma = prismaInstance; }

  public async fetchPathsTouchingJWT(assessmentId: string): Promise<any[]> {
    return await this.prisma.jWTGraph.findMany({
      where: { assessmentId },
      orderBy: { timestamp: 'desc' }
    });
  }

  public async fetchAllFunctionsReachingLogin(assessmentId: string): Promise<any[]> {
    return await this.prisma.functionInventory.findMany({
      where: {
        assessmentId,
        name: { contains: 'login' }
      }
    });
  }

  public async fetchCryptoOperationsByType(assessmentId: string, cipherType: string): Promise<any[]> {
    return await this.prisma.cryptoOperation.findMany({
      where: {
        assessmentId,
        type: { equals: cipherType }
      }
    });
  }
}
