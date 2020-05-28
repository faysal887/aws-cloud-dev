import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler } from 'aws-lambda'
import {getAllAdItems} from '../../mainLogic/ads'


export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  // TODO: Get all AD items 
  const authorization = event.headers.Authorization
  const split = authorization.split(' ')
  const jwtToken = split[1] 
  console.log(jwtToken)
  const result = await getAllAdItems()
    
  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
      items: result
    })
  }
}
