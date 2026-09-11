import * as http from 'node:http';
import { AdmissionEvaluator } from './evaluator.js';
import type {
  AdmissionControllerConfig,
  AdmissionRequest,
  AdmissionResponse,
  AdmissionReview,
} from './types.js';

export class AdmissionServer {
  private evaluator: AdmissionEvaluator;
  private config: AdmissionControllerConfig;
  private server?: http.Server;

  constructor(config: AdmissionControllerConfig, evaluator?: AdmissionEvaluator) {
    this.config = config;
    this.evaluator = evaluator ?? new AdmissionEvaluator(config);
  }

  public async handleReview(review: AdmissionReview): Promise<AdmissionReview> {
    const request = review.request;
    if (!request) {
      return {
        apiVersion: 'admission.k8s.io/v1',
        kind: 'AdmissionReview',
        response: {
          uid: 'unknown',
          allowed: this.config.failurePolicy === 'Ignore',
          status: {
            code: 400,
            message: 'Malformed AdmissionReview: missing request body',
          },
        },
      };
    }

    const outcome = await this.evaluator.evaluate(request);

    const response: AdmissionResponse = {
      uid: request.uid,
      allowed: outcome.allowed,
    };

    if (!outcome.allowed) {
      response.status = {
        code: 403,
        message: `Deployment rejected by ai-security-architect admission controller (${outcome.violations.join('; ')})`,
        reason: 'SecurityBudgetViolation',
      };
    }

    if (outcome.mode === 'dry-run' && outcome.violations.length > 0) {
      response.warnings = [
        `[DRY-RUN SECURITY WARNING] ${outcome.violations.join('; ')}`,
      ];
    }

    return {
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      response,
    };
  }

  public start(port: number = 8443): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        if (req.method === 'POST' && req.url === '/validate') {
          let body = '';
          req.on('data', (chunk) => {
            body += chunk;
            if (body.length > 1024 * 1024) {
              // 1MB request body limit to prevent DoS
              res.writeHead(413, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Payload Too Large' }));
              req.destroy();
            }
          });

          req.on('end', async () => {
            try {
              const review = JSON.parse(body) as AdmissionReview;
              const result = await this.handleReview(review);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify(result));
            } catch (err) {
              const fallbackAllowed = this.config.failurePolicy === 'Ignore';
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(
                JSON.stringify({
                  apiVersion: 'admission.k8s.io/v1',
                  kind: 'AdmissionReview',
                  response: {
                    uid: 'error',
                    allowed: fallbackAllowed,
                    status: { code: 500, message: String(err) },
                  },
                })
              );
            }
          });
        } else if (req.method === 'GET' && req.url === '/healthz') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('OK');
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      this.server.listen(port, () => resolve());
      this.server.on('error', reject);
    });
  }

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
