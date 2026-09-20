import { ExtractedEndpoint } from '../types';

export function extractEndpointsFromStrings(
  strings: string[],
  sourceContext = 'classes.dex'
): ExtractedEndpoint[] {
  const endpoints: ExtractedEndpoint[] = [];
  const seen = new Set<string>();

  // Regex patterns
  const urlRegex = /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)/gi;
  const wsRegex = /wss?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)/gi;
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{2,5})?(?:\/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?\b/g;
  const apiPathRegex = /^(?:\/api\/(?:v\d+|v\d+\.\d+)?\/[a-zA-Z0-9_/.-]+|\/v\d+\/[a-zA-Z0-9_/.-]+|\/auth\/[a-zA-Z0-9_/.-]+|\/graphql|\/oauth\/[a-zA-Z0-9_/.-]+|\/rest\/[a-zA-Z0-9_/.-]+)/i;
  const deepLinkRegex = /^[a-zA-Z0-9_-]+:\/\/[a-zA-Z0-9_./-]+/;

  for (const rawStr of strings) {
    if (!rawStr || rawStr.length < 4 || rawStr.length > 500) continue;
    const str = rawStr.trim();

    // 1. Check for standard HTTP/HTTPS URLs
    const urlMatches = str.match(urlRegex);
    if (urlMatches) {
      for (const u of urlMatches) {
        if (!isValidEndpoint(u) || seen.has(u)) continue;
        seen.add(u);
        endpoints.push(categorizeUrl(u, sourceContext));
      }
    }

    // 2. Check for WebSockets
    const wsMatches = str.match(wsRegex);
    if (wsMatches) {
      for (const w of wsMatches) {
        if (seen.has(w)) continue;
        seen.add(w);
        endpoints.push({
          url: w,
          type: 'websocket',
          protocol: w.startsWith('wss://') ? 'WSS (Secure)' : 'WS (Insecure)',
          isInsecure: w.startsWith('ws://'),
          category: 'API / Backend',
          sourceFile: sourceContext,
        });
      }
    }

    // 3. Check for standalone IP Addresses
    const ipMatches = str.match(ipRegex);
    if (ipMatches) {
      for (const ip of ipMatches) {
        // Skip common false positives like version numbers '1.0.0.0' or subnet masks if irrelevant
        if (ip.startsWith('0.0.0.0') || ip.startsWith('127.0.0.1') || ip.startsWith('255.255.255')) continue;
        if (seen.has(ip)) continue;
        seen.add(ip);
        endpoints.push({
          url: ip,
          type: 'ip_address',
          protocol: 'TCP / IP',
          host: ip.split(':')[0],
          isInsecure: true,
          category: 'IP Host',
          sourceFile: sourceContext,
        });
      }
    }

    // 4. Check for Internal API routes
    if (apiPathRegex.test(str)) {
      if (!seen.has(str) && !str.includes(' ') && !str.includes('{') && !str.includes('<')) {
        seen.add(str);
        endpoints.push({
          url: str,
          type: 'internal_api',
          protocol: 'REST / Internal Route',
          path: str,
          isInsecure: false,
          category: 'API / Backend',
          sourceFile: sourceContext,
        });
      }
    }

    // 5. Deep links & custom schemes
    if (deepLinkRegex.test(str) && !str.startsWith('http') && !str.startsWith('ws') && !str.startsWith('android') && !str.startsWith('schema')) {
      if (!seen.has(str) && str.length < 80) {
        seen.add(str);
        endpoints.push({
          url: str,
          type: 'deep_link',
          protocol: str.split('://')[0].toUpperCase(),
          isInsecure: false,
          category: 'Custom Protocol',
          sourceFile: sourceContext,
        });
      }
    }
  }

  return endpoints;
}

function categorizeUrl(url: string, sourceFile: string): ExtractedEndpoint {
  const isInsecure = url.startsWith('http://');
  let category: ExtractedEndpoint['category'] = 'API / Backend';
  let host = '';

  try {
    const parsed = new URL(url);
    host = parsed.hostname;

    if (host.includes('s3.amazonaws.com') || host.includes('blob.core.windows.net') || host.includes('storage.googleapis.com')) {
      category = 'Cloud Storage';
    } else if (host.includes('firebaseio.com') || host.includes('supabase.co') || host.includes('auth0.com') || host.includes('cognito')) {
      category = 'Auth Service';
    } else if (host.includes('google-analytics') || host.includes('segment.io') || host.includes('mixpanel') || host.includes('appsflyer') || host.includes('adjust.com') || host.includes('facebook') || host.includes('crashlytics')) {
      category = 'Analytics & Ads';
    } else if (host.includes('cloudfront.net') || host.includes('akamai') || host.includes('cloudflare') || host.includes('fastly')) {
      category = 'CDN';
    }
  } catch {
    // fallback
  }

  return {
    url,
    type: 'external_url',
    protocol: isInsecure ? 'HTTP (Insecure)' : 'HTTPS (Encrypted)',
    host,
    isInsecure,
    category,
    sourceFile,
  };
}

function isValidEndpoint(url: string): boolean {
  // Filter out XML namespaces, schema defs, xmlns
  if (url.includes('schemas.android.com')) return false;
  if (url.includes('w3.org')) return false;
  if (url.includes('apache.org/licenses')) return false;
  if (url.includes('example.com') && !url.includes('api')) return false;
  if (url.includes('xmlns:')) return false;
  return true;
}
