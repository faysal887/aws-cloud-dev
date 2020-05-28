import * as uuid from 'uuid'
import { TodoItem } from '../models/TodoItem'
import { TodoAccess } from '../dataLayer/todoAccess'
import { CreateTodoRequest } from '../requests/CreateTodoRequest'
import { UpdateTodoRequest } from '../requests/UpdateTodoRequest'
import { parseUserId } from '../auth/utils'
import { TodoUpdate } from '../models/TodoUpdate'
import { TodoS3 } from '../dataLayer/todosS3'


const todoAccess = new TodoAccess()
const s3Access = new TodoS3()

export async function getAllTodoItems(jwtToken: string): Promise<TodoItem[]> {
  const userId = parseUserId(jwtToken)
  return todoAccess.getAllTodoItems(userId)
}

export async function deleteTodoItem(jwtToken:string,todoId: string): Promise<TodoItem[]> {
  const userId = parseUserId(jwtToken)
  return await todoAccess.deleteTodoItem(userId,todoId)
}
export async function updateTodoItem(jwtToken:string,todoId: string, updateTodoItem: UpdateTodoRequest): Promise<any> {
  const userId = parseUserId(jwtToken)
  updateTodoItem as TodoUpdate
  return await todoAccess.updateTodoItem(userId,todoId,updateTodoItem)
}
export async function createTodoItem(
  createTodoRequest: CreateTodoRequest,
  jwtToken: string
): Promise<TodoItem> {

  const itemId = uuid.v4()
  const userId = parseUserId(jwtToken)

  return await todoAccess.createTodoItem({
    todoId: itemId,
    userId: userId,
    name: createTodoRequest.name,
    createdAt: new Date().toISOString(),
    dueDate: createTodoRequest.dueDate,
    done: false
  })
}

export async  function generateImageURL(
  todoId: string,
  jwtToken: string
): Promise<string> {
  const {url, bucketName} = JSON.parse(s3Access.generateImageURL(todoId))
  const userId = parseUserId(jwtToken)
  await todoAccess.updateImageURL(userId, todoId, bucketName)
  return url
}

