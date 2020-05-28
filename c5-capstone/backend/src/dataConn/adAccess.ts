import * as AWS  from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'
import { createLogger } from '../utils/logger'
const logger = createLogger('dataLogger')

const XAWS = AWSXRay.captureAWS(AWS)

import { AdItem } from '../models/AdItem'
import { AdUpdate } from '../models/AdUpdate'


export class AdAccess {

  constructor(
    private readonly docClient: DocumentClient = createDynamoDBClient(),
    private readonly adItemsTable = process.env.ADS_TABLE,
    private readonly adItemsIndex = process.env.ADS_INDEX) {
  }

  async getAllAdItems(): Promise<AdItem[]> {
    logger.info('Getting all ad items')

    const result = await this.docClient.scan({
        TableName: this.adItemsTable
      })
      .promise()

    const items = result.Items
    return items as AdItem[]
  }

  async getUserAdItems(userId:string): Promise<AdItem[]> {
    logger.info('Getting all user ad items')

    const result = await this.docClient.query({
        TableName: this.adItemsTable,
        IndexName: this.adItemsIndex,
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
          ':userId': userId
        }
      })
      .promise()

    const items = result.Items
    return items as AdItem[]
  }

async updateAdItem(userId:string, adId:string, updateItem:AdUpdate): Promise<any> {
  logger.info(`updating ${JSON.stringify(updateItem)} with Id ${adId} of user ${userId}`)

  try{
    const result = await this.docClient.update({
        TableName: this.adItemsTable,
        UpdateExpression: "set #name = :name, #reference_url=:reference_url, price=:price, email=:email",
        ExpressionAttributeValues:{
        ":name":updateItem.name,
        ":reference_url":updateItem.reference_url,
        ":price":updateItem.price,
        ":email": updateItem.email
    },
        ExpressionAttributeNames: {"#name": "name", "#reference_url":"reference_url"},
        Key: { userId, adId },
        ReturnValues:"UPDATED_NEW"
      }).promise()
    
    logger.info(`updated item ${JSON.stringify(result)}`)
    
    return result.Attributes

    }catch(error){
    logger.error(`error ${JSON.stringify(error)}`)

    return {"message":"error occured"}
    }
      
  }

  async deleteAdItem(userId:string,adId:string): Promise<any> {
    logger.info(`delete item with Id ${adId} of user ${userId}`)

    const result = await this.docClient.delete({
        TableName: this.adItemsTable,
        Key: { userId, adId }
      }).promise()

      logger.info(`deleted item ${result}`)
    return null
  }

  async createAdItem(adItem: AdItem): Promise<AdItem> {
    logger.info(`creating a ad item ${JSON.stringify(adItem)}`)
    await this.docClient.put({
      TableName: this.adItemsTable,
      Item: adItem
    }).promise()
    
    return adItem
  }
  async updateImageURL(userId:string, adId:string, bucketName:string): Promise<any> {
    logger.info(`adding image url  with Id ${adId} of user ${userId}`)

  try{
    const result = await this.docClient.update({
        TableName: this.adItemsTable,
        UpdateExpression: "set attachmentUrl=:attachmentUrl",
        ExpressionAttributeValues:{
        ":attachmentUrl":`https://${bucketName}.s3.amazonaws.com/${adId}`
    },
        Key: { userId, adId },
        ReturnValues:"UPDATED_NEW"
      }).promise()
    
    logger.info(`updated item ${JSON.stringify(result)}`)
    return true

    }catch(error){
    logger.error(`error ${JSON.stringify(error)}`)

    return false
    }
      
  }
}

function createDynamoDBClient() {
  if (process.env.IS_OFFLINE) {
    logger.info('Creating a local DynamoDB instance')
    return new XAWS.DynamoDB.DocumentClient({
      region: 'localhost',
      endpoint: 'http://localhost:8000'
    })
  }

  return new XAWS.DynamoDB.DocumentClient()
}
