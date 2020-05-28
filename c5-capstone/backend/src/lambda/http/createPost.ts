import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda'
import {createAdItem} from '../../mainLogic/ads'
import { PostCreateReq } from '../../requests/PostCreateReq'

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const newAd: PostCreateReq = JSON.parse(event.body)
  // TODO: Implement creating a new TODO item
  const authorization = event.headers.Authorization
  const split = authorization.split(' ')
  const jwtToken = split[1] 
  const result = await createAdItem(newAd,jwtToken)

  return {
    statusCode: 201,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
      item: result
    })
  }
}
