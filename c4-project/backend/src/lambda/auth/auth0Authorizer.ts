import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
//import Axios from 'axios'
//import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJTlnILNoaCyDOMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi1rZ3RnaTBhbC5hdXRoMC5jb20wHhcNMjAwNTE1MjAxNTQyWhcNMzQw
MTIyMjAxNTQyWjAhMR8wHQYDVQQDExZkZXYta2d0Z2kwYWwuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxtkeLoghR2PcHHh8tt9PLpCk
6MSRGeS+1Moy2M7t8o5SCpBbBZO2jQVNP4jBM4939qZF1ndf2BJOyCaCPxYkb3SW
RxEeEbuwyUzWIOLO4voVbVnA51e/6KTzhNaGBB1l8To5n5uWv26PNHrKUMJJmeIu
5Fmgk6XobewnsHAq8NGViiihSpUj7fw0yXqErCewocXqCX+EQj/9SlDQ93UK4x1c
ykTG7E0svBrL5S4Hc4wV4rMnt4R3wn8VG/bt+hq/y4HhBTSJX0DgJJ8SVt7s89uA
Q718WSxR93OYzwuo7/lTLvpy8qN16hCrss1MbvS74ud+LLBCRdjQANkV4kcKkwID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR15uekFkioYWawYtsZ
yreLc4VpDzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAKAaz0QC
9LnvP8VSBSfGLK5lAJcpl1Hjl9bDs5yef3wWM/gvCjDTg3SUvJq02Rswqk4rO1hx
HQ0bs22lDXJV3KD1Q6JZqUsSvU+KcSldzU+O0s5VxFSRGkoL5eDr+nJclrGU392E
BJt2HdE9IHNpiVl8t009ariDOt+K2EQSTvi+9Dh87OTLBei5Lsdc/Dx1qfHCVrne
O18cvXs4OXHgKcaKrPg2yetzywQGJCjz/ZQh+h4n4ZshRqYuOVq2F4kHyTtBS6Lt
vmZPzQG3g46mRnUXBMBaqZp0vXCevOjG15ifIshFr1STx1XIGCqf6llllRMobcfO
vD3ZTEsaTGqYH3k=
-----END CERTIFICATE-----`

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
//const jwksUrl = 'https://dev-4sdbcy83.auth0.com/.well-known/jwks.json'

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  //const jwt: Jwt = decode(token, { complete: true }) as Jwt
  //const jwksPayload =  Axios.get(jwksUrl)
  //const certurl =  jwksPayload['keys'][0]['x5c'][0]
  //console.log(`cert ${certurl}`)

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
