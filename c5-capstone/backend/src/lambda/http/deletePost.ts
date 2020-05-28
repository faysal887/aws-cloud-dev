import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler } from 'aws-lambda'
import {deleteAdItem} from '../../mainLogic/ads'
export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const adId = event.pathParameters.adId
  const authorization = event.headers.Authorization
  const split = authorization.split(' ')
  const jwtToken = split[1] 
  
  await deleteAdItem(jwtToken,adId)
  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
     
    })
  }
}
