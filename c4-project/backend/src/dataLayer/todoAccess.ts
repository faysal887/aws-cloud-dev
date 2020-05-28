import * as AWS  from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
import { DocumentClient } from 'aws-sdk/clients/dynamodb'
import { createLogger } from '../utils/logger'
const logger = createLogger('dataLogger')

const XAWS = AWSXRay.captureAWS(AWS)

import { TodoItem } from '../models/TodoItem'
import { TodoUpdate } from '../models/TodoUpdate'

export class TodoAccess {

  constructor(
    private readonly docClient: DocumentClient = createDynamoDBClient(),
    private readonly todoItemsTable = process.env.TODOS_TABLE,
    private readonly todoItemsIndex = process.env.TODOS_INDEX) {
  }

  async getAllTodoItems(userId:string): Promise<TodoItem[]> {
    logger.info('Getting all todo items')

    const result = await this.docClient.query({
        TableName: this.todoItemsTable,
        IndexName: this.todoItemsIndex,
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
          ':userId': userId
        }
      })
      .promise()

    const items = result.Items
    return items as TodoItem[]
  }

  async updateTodoItem(userId:string, todoId:string, updateItem:TodoUpdate): Promise<any> {
    logger.info(`updating ${JSON.stringify(updateItem)} with Id ${todoId} of user ${userId}`)

  try{
    const result = await this.docClient.update({
        TableName: this.todoItemsTable,
        UpdateExpression: "set #name = :name, dueDate=:dueDate, done=:done",
        ExpressionAttributeValues:{
        ":name":updateItem.name,
        ":dueDate":updateItem.dueDate,
        ":done":updateItem.done
    },
        ExpressionAttributeNames: {"#name": "name"},
        Key: { userId, todoId },
        ReturnValues:"UPDATED_NEW"
      }).promise()
    
    logger.info(`updated item ${JSON.stringify(result)}`)
    
    return result.Attributes

    }catch(error){
    logger.error(`error ${JSON.stringify(error)}`)

    return {"message":"error occured"}
    }
      
  }

  async deleteTodoItem(userId:string,todoId:string): Promise<any> {
    logger.info(`delete item with Id ${todoId} of user ${userId}`)

    const result = await this.docClient.delete({
        TableName: this.todoItemsTable,
        Key: { userId, todoId }
      }).promise()

      logger.info(`deleted item ${result}`)
    return null
  }

  async createTodoItem(todoItem: TodoItem): Promise<TodoItem> {
    logger.info(`creating a todo item ${JSON.stringify(todoItem)}`)
    await this.docClient.put({
      TableName: this.todoItemsTable,
      Item: todoItem
    }).promise()
    
    return todoItem
  }
  async updateImageURL(userId:string, todoId:string, bucketName:string): Promise<any> {
    logger.info(`adding image url  with Id ${todoId} of user ${userId}`)

  try{
    const result = await this.docClient.update({
        TableName: this.todoItemsTable,
        UpdateExpression: "set attachmentUrl=:attachmentUrl",
        ExpressionAttributeValues:{
        ":attachmentUrl":`https://${bucketName}.s3.amazonaws.com/${todoId}`
    },
        Key: { userId, todoId },
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
