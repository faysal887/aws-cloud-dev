import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda'
import { PostUpdateReq } from '../../requests/PostUpdateReq'
import {updateAdItem} from '../../mainLogic/ads'

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const adId = event.pathParameters.adId
  const updatedAd: PostUpdateReq = JSON.parse(event.body)
  const authorization = event.headers.Authorization
  const split = authorization.split(' ')
  const jwtToken = split[1] 
  const item = await updateAdItem(jwtToken,adId,updatedAd)

  // TODO: Update a TODO item with the provided id using values in the "updatedTodo" object
  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
     item
    })
  }
}
