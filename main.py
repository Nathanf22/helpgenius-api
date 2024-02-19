import os, shutil
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile, status, Path
import mimetypes
from typing import Annotated
from pydantic import BaseModel
from fastapi.responses import FileResponse, JSONResponse
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import aioredis
from fastapi.middleware.cors import CORSMiddleware
from os import environ as env
from google.cloud import redis_v1
from dotenv import load_dotenv
import asyncio

load_dotenv()
app = FastAPI()

origins = ["http://localhost:8080", "https://helpgenius.web.app/"]  # Mettez ici l'URL de votre application Flutter
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],  # Vous pouvez spécifier les méthodes HTTP que vous souhaitez autoriser
    allow_headers=["*"],  # Vous pouvez spécifier les en-têtes HTTP que vous souhaitez autoriser
)

# Configuration de la connexion Redis
# REDIS_URL = "redis://localhost:6379"




# auth_credentials = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
# projet = os.environ.get('GOOGLE_CLOUD_PROJECT')
# instance_id = os.environ.get('REDIS_INSTANCE_ID')
# location = os.environ.get('LOCATION')



# redis_client = redis_v1.CloudRedisAsyncClient(credentials=auth_credentials)
# instance_path = redis_client.instance_path(project=projet,location=location, instance=instance_id)

######### UNCOMMENT FOR PRODUCTION ################### 
redis_host = os.environ.get("REDISHOST", "localhost")
redis_port = int(os.environ.get("REDISPORT", 6379))
redis = aioredis.StrictRedis(host=redis_host, port=redis_port)

######## UNCOMMENT FOR LOCAL TEST #######
# REDIS_URL ="redis://localhost:6379"
# redis = aioredis.from_url(REDIS_URL)

# Fonction dépendante pour obtenir la connexion Redis
async def get_redis():
    # redis = await redis_client.connect(instance_path)
    return await redis

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "3d8cb47c0ddf20f6146c3565fb7c113086b90260ddbfdeab8db931cc137e47c7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
upload_folder = "/home/nathan/Projects/upload/"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


'''
LIST OF ENDPOINTS:
    post /agents/{agent_id}/upload ::  Add a file to the agent
    get /agents/{agent_id}/file_list :: Get the list of {agent_id} file
    get /agents/{agent_id}/file/{file_name} :: Get file {file_name} of agent {agent_id}
    delete /agents/{agent_id}/file/{file_name} :: Delete file {file_name} of agent {agent_id} 
    put /agents/{agent_id}/text ::  Modify the text of an agent
    get /agents/{agent_id}/text  :: Get the text of an agent
    put /agents/{agent_id}/instruction ::  Modify the instruction of an agent
    get /agents/{agent_id}/instruction ::  Get the instruction of an agent
    post /agents/{agent_id}/link :: Add a link to an agent
    get /agents/{agent_id}/link_list :: Get the list of link, each link with id
    delete /agents/{agent_id}/link/{link_id} :: Delete the link with id {link_id}
    post /agents/{agent_name} :: Create a new agent
    post /agents/{agent_id}/description/{agent_description} :: Add a description to an agent
    ##get /agents :: Get the list of agent of the current account
    put /models/{model_name} :: add a model to the model_list
    get /models/list :: get the list of available generative model
    get /agents/{agent_id} :: get agent information by id
    put /agents/{agent_id}/model/{model_id}  :: Modify the model used by the agent
    delete /agents/{agent_id} :: Delete the agent {agent_id}
    post /agents/{agent_id}/message  :: talk to the agent
    get /agents/{agent_id}/response/{response_id} :: get the response of the client


    CREATION DE COMPTE:
    post /developer  :: create an acount for a developer, require the email, and a name
    post /enterprise :: create an account for an enterprise, require a business email, and the enterprise name


    get /developer/{developer_id}/api_key_list :: get the list of api key for the account
    get /developer/{developer_id}/new_api_key  :: generate a new API key for the developer
    delete /developer/{developer_id}/api_key/{api_key_id}  :: delete the api_key



'''

def get_agent_response(message: str) -> str:
    # Implement your logic here to process the message and generate the agent's response
    # For now, let's just echo the message as the response
    return f"Agent received message: {message}"

async def get_message_history(agent_id: str, user_id: str, redis: aioredis.Redis):
    try:
        # Get the message counter for the user
        message_counter = await redis.get(f"agent:{agent_id}:user:{user_id}:message_counter")
        if message_counter is None:
            return None  # No history available for the user

        message_counter = int(message_counter)

        # Retrieve the message and response history
        history = []
        # for i in range(message_counter + 1):
        #     message = await redis.lindex(f"agent:{agent_id}:user:{user_id}:messages", i, encoding="utf-8")
        #     response = await redis.get(f"agent:{agent_id}:user:{user_id}:response:{i}", encoding="utf-8")
        #     history.append({"message": message, "response": response})
        for i in range(message_counter):
            # Récupérer le message
            message = await redis.lindex(f"agent:{agent_id}:user:{user_id}:messages", i)
            if message is not None:
                message = message.decode('utf-8')
            
            # Récupérer la réponse
            response = await redis.get(f"agent:{agent_id}:user:{user_id}:response:{i+1}")
            if response is not None:
                response = response.decode('utf-8')

            # Ajouter à l'historique
            history.append({"message": message, "response": response})

        return history

    except Exception as e:
        # Handle exceptions appropriately (log, raise, etc.)
        raise e

@app.get("/")
async def root():
    return {"message": "root"}

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



#post /agents/{agent_id}/upload ::  Add a file to the agent
@app.post("/agents/{agent_id}/upload")
# async def upload_file(file: UploadFile, current_user: Annotated[User, Depends(get_current_active_user)], force: bool = False):
async def upload_file(file: UploadFile, agent_id: str, force: bool = False):
    try:
        # Vérifiez si
        #  le répertoire de destination existe, sinon créez-le
        os.makedirs(upload_folder  + agent_id + "/", exist_ok=True)

        # Chemin complet du fichier sur le serveur
        file_path = os.path.join(upload_folder + agent_id + "/", file.filename)

        # Vérifiez le type de contenu (Content-Type) du fichier
        mime_type, _ = mimetypes.guess_type(file.filename)

        # Liste des types MIME acceptés pour Excel et LibreOffice
        accepted_mimes = [
            "application/pdf", #PDF
            "application/msword",  #WORD
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document", #.docx
            # "application/vnd.ms-excel",  # XLS
            # "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",  # XLSX
            # "application/vnd.oasis.opendocument.spreadsheet",  # ODS
            # "text/csv",  # CSV
            # Ajoutez d'autres types MIME acceptés ici
        ]

        # Vérifiez si le type de contenu est parmi les types MIME acceptés
        if mime_type not in accepted_mimes:
            json_response = {
                'status': 'fail',
                'message': 'Le fichier doit être un format pris en charge (PDF, WORD).',
                'status_code': 400,
            }
            return JSONResponse(content=json_response, status_code=400)

        # Vérifiez si un fichier du même nom existe déjà
        if os.path.exists(file_path) and force == False:
            # print("File exists")
            json_response = {
                'status': 'fail',
                'message': 'le fichier existe deja',
                'status_code': 409,
            }
            return JSONResponse(content=json_response, status_code=409)
    
        else:
            # Enregistrez le fichier uploadé
            json_response = {
                'status': 'success',
                'message': 'Fichier enregistré avec succès!',
                'status_code': 200,
            }
            with open(file_path, "wb") as file_object:
                shutil.copyfileobj(file.file, file_object)

            return JSONResponse(content=json_response, status_code=200)
    except Exception as e:
        json_response = {
                'status': 'fail',
                'message': str(e),
                'status_code': 500,
            }
        return JSONResponse(content=json_response, status_code=500)
    

#get /agents/{agent_id}/file_list :: Get the list of {agent_id} file
@app.get("/agents/{agent_id}/file_list")
async def get_file_list(agent_id: str = Path(..., description="Agent ID")):
    try:
        # Chemin complet du répertoire de l'agent sur le serveur
        agent_folder_path = os.path.join(upload_folder, agent_id)

        # Vérifiez si le répertoire de l'agent existe
        if not os.path.exists(agent_folder_path):
            json_response = {
                'status': 'fail',
                'message': 'Agent not found',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Liste des fichiers dans le répertoire de l'agent
        files_list = []
        for filename in os.listdir(agent_folder_path):
            file_path = os.path.join(agent_folder_path, filename)

            # Obtenir la taille du fichier en octets
            file_size = os.path.getsize(file_path)

            # Obtenir le format du fichier
            _, file_format = os.path.splitext(filename)

            # Ajouter les informations du fichier à la liste
            files_list.append({
                'name': filename.split(".")[0],
                'size': file_size,
                'format': file_format[1:],  # Supprimer le point du début de l'extension
            })

        # Réponse réussie avec la liste des fichiers
        json_response = {
            'status': 'success',
            'message': f'Liste des fichiers pour {agent_id}',
            'files': files_list,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)
    except Exception as e:
        # Gestion des erreurs
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


#get /agents/{agent_id}/file/{file_name} :: Get file {file_name} of agent {agent_id}
@app.get("/agents/{agent_id}/file/{file_name}")
async def get_file(agent_id: str = Path(..., description="Agent ID"), file_name: str = Path(..., description="File Name")):
    try:
        # Chemin complet du fichier sur le serveur
        file_path = os.path.join(upload_folder, agent_id, file_name)

        # Vérifiez si le fichier existe
        if not os.path.exists(file_path):
            json_response = {
                'status': 'fail',
                'message': 'Fichier non trouvé',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Renvoie le fichier comme réponse
        return FileResponse(file_path, filename=file_name)

    except HTTPException as e:
        # Renvoie une réponse d'erreur avec le détail fourni par l'exception
        json_response = {
            'status': 'fail',
            'message': str(e.detail),
            'status_code': e.status_code,
        }
        return JSONResponse(content=json_response, status_code=e.status_code)
    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


#delete /agents/{agent_id}/file/{file_name} :: Delete file {file_name} of agent {agent_id} 
@app.delete("/agents/{agent_id}/file/{file_name}")
async def delete_file(agent_id: str = Path(..., description="Agent ID"), file_name: str = Path(..., description="File Name")):
    try:
        # Chemin complet du fichier sur le serveur
        file_path = os.path.join(upload_folder, agent_id, file_name)

        # Vérifiez si le fichier existe
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"File {file_name} not found")

        # Supprimez le fichier
        os.remove(file_path)

        # Réponse de succès
        json_response = {
            'status': 'success',
            'message': f'Fichier {file_name} supprimé avec succès pour l\'agent {agent_id}',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except HTTPException as e:
        # Renvoie une réponse d'erreur avec le détail fourni par l'exception
        json_response = {
            'status': 'fail',
            'message': str(e.detail),
            'status_code': e.status_code,
        }
        return JSONResponse(content=json_response, status_code=e.status_code)
    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
#put /agents/{agent_id}/text ::  Modify the text of an agent
@app.put("/agents/{agent_id}/text")
async def update_agent_text(agent_id: str = Path(..., description="Agent ID"), 
                            text: str = Form(..., description="New Text"),
                            redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Stockez le texte dans Redis
        key = f'agent:{agent_id}:text'
        redis.set(key, text)

        # Réponse de succès
        json_response = {
            'status': 'success',
            'message': f'Texte de l\'agent {agent_id} mis à jour avec succès',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    

#get /agents/{agent_id}/text  :: Get the text of an agent
@app.get("/agents/{agent_id}/text")
async def get_agent_text(agent_id: str = Path(..., description="Agent ID"), 
                         redis: aioredis.Redis = Depends(get_redis)):
    try:
        key = f'agent:{agent_id}:text'
        # Récupérez le texte de l'agent depuis Redis
        text = redis.get(key)

        # Si l'agent n'a pas de texte, renvoyez une réponse avec un statut 404 (Not Found)
        if text is None:
            json_response = {
                'status': 'fail',
                'message': f'Texte de l\'agent {agent_id} introuvable',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Réponse de succès avec le texte de l'agent
        json_response = {
            'status': 'success',
            'message': f'Texte de l\'agent {agent_id} récupéré avec succès',
            'text': text.decode('utf-8'),  # Convertir bytes à str si nécessaire
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
#put /agents/{agent_id}/instruction ::  Modify the instruction of an agent
@app.put("/agents/{agent_id}/instruction")
async def update_agent_text(agent_id: str = Path(..., description="Agent ID"), 
                            instruction_text: str = Form(..., description="New Text"),
                            redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Stockez le texte dans Redis
        key = f'agent:{agent_id}:instruction_text'
        redis.set(key, instruction_text)

        # Réponse de succès
        json_response = {
            'status': 'success',
            'message': f'Instruction de l\'agent {agent_id} mis à jour avec succès',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


#get /agents/{agent_id}/instruction ::  Get the instruction of an agent
@app.get("/agents/{agent_id}/instruction")
async def get_agent_text(agent_id: str = Path(..., description="Agent ID"), 
                         redis: aioredis.Redis = Depends(get_redis)):
    try:
        key = f'agent:{agent_id}:instruction_text'
        # Récupérez le texte de l'agent depuis Redis
        text = redis.get(key)

        # Si l'agent n'a pas de texte, renvoyez une réponse avec un statut 404 (Not Found)
        if text is None:
            json_response = {
                'status': 'fail',
                'message': f'Instruction de l\'agent {agent_id} introuvable',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Réponse de succès avec le texte de l'agent
        json_response = {
            'status': 'success',
            'message': f'Instruction de l\'agent {agent_id} récupéré avec succès',
            'text': text.decode('utf-8'),  # Convertir bytes à str si nécessaire
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


#post /agents/{agent_id}/link :: Add a link to an agent
@app.post("/agents/{agent_id}/link")
async def add_link_to_agent(
    agent_id: str = Path(..., description="Agent ID"),
    link: str = Form(..., description="Link URL"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Incrémentez le lien ID (auto-incrémenté)
        link_id = await redis.incr(f"agent:{agent_id}:link_id")

        # Stockez le lien dans la clé correspondante
        link_key = f"agent:{agent_id}:link:{link_id}"
        await redis.set(link_key, link)

        # Réponse de succès avec l'ID du lien
        json_response = {
            'status': 'success',
            'message': 'Lien ajouté avec succès',
            'link_id': link_id,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Renvoie une réponse d'erreur générique en cas d'erreur inattendue
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#get /agents/{agent_id}/link_list :: Get the list of link, each link with id
@app.get("/agents/{agent_id}/link_list", response_model=list)
async def get_link_list(agent_id: str = Path(..., description="Agent ID"), redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Retrieve the link count for the agent
        link_count = await redis.get(f"agent:{agent_id}:link_id")

        if link_count is None:
            # If there are no links, return an empty list
            json_response = {
                'status': 'success',
                'message': 'No link Found',
                'link_list': [],
                'status_code': 200,
            }
            return JSONResponse(content=json_response, status_code=200)
        link_count = int(link_count)

        # Construct the list of links with their corresponding IDs
        link_list = [
                     {"link_id": link_id, 
                      "link": (await redis.get(f"agent:{agent_id}:link:{link_id}")).decode('ascii') if (await redis.get(f"agent:{agent_id}:link:{link_id}")) is not None else None } 
                      for link_id in range(1, link_count + 1)
                      ]

        json_response = {
            'status': 'success',
            'message': 'Link(s) retrieved successfuly',
            'link_list': link_list,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#delete /agents/{agent_id}/link/{link_id} :: Delete the link with id {link_id}
@app.delete("/agents/{agent_id}/link/{link_id}", response_model=dict)
async def delete_link(
    agent_id: str = Path(..., description="Agent ID"),
    link_id: int = Path(..., description="Link ID"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Check if the link ID exists
        link_key = f"agent:{agent_id}:link:{link_id}"
        if not await redis.exists(link_key):
            raise HTTPException(status_code=404, detail="Link not found")

        # Delete the link
        await redis.delete(link_key)

        # Respond with success
        json_response = {
            'status': 'success',
            'message': f'Link with ID {link_id} deleted successfully',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except HTTPException as e:
        # Re-raise HTTPException to return a specific error response
        raise e

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
#post /agents/{agent_name} :: Create a new agent
@app.post("/agents/{agent_name}", response_model=dict)
async def create_agent(
    agent_name: str = Path(..., description="Agent Name"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Get the current agent ID (auto-incremented)
        agent_id = await redis.incr("global:agent_id")

        # Store the agent name in Redis
        await redis.set(f"agent:{agent_id}:name", agent_name)

        # Respond with success and the assigned agent ID
        json_response = {
            'status': 'success',
            'message': f'Agent {agent_name} created successfully',
            'agent_id': agent_id,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
#post /agents/{agent_id}/description/{agent_description} :: Add a description to an agent
@app.post("/agents/{agent_id}/description/{agent_description}", response_model=dict)
async def add_agent_description(
    agent_id: int = Path(..., description="Agent ID"),
    agent_description: str = Path(..., description="Agent Description"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Store the agent description in Redis
        await redis.set(f"agent:{agent_id}:description", agent_description)

        # Respond with success
        json_response = {
            'status': 'success',
            'message': f'Description added to agent {agent_id} successfully',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
#put /models/{model_name} :: add a model to the model_list
@app.put("/models/{model_name}", response_model=dict)
async def add_model_to_list(
    model_name: str = Path(..., description="Model Name"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Get the current model ID (auto-incremented)
        model_id = redis.incr("global:model_id")

        # Store the model name in Redis
        redis.set(f"model:{model_id}:name", model_name)

        # Respond with success and the assigned model ID
        json_response = {
            'status': 'success',
            'message': f'Model {model_name} added to the model list successfully',
            'model_id': model_id,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#get /agents :: get the list of agents
@app.get("/agents")
async def get_model_list(redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Get the list of model IDs
        
        agent_ids = await redis.keys("agent:*:name")
        # print(model_ids)
        # return JSONResponse(content=model_ids, status_code=200)
        # Extract model information (ID and name) from Redis
        agent_list = [
                {
                    "agent_id": int(agent_id.split(b':')[1].decode('ascii')),
                    "agent_name": (await redis.get(agent_id)).decode('ascii'),
                    "agent_description": (await redis.get(':'.join(agent_id.decode('ascii').split(':')[0:-1])+':description')).decode('ascii') if (await redis.get(':'.join(agent_id.decode('ascii').split(':')[0:-1])+':description')) is not None else None
                } 
                for agent_id in agent_ids
            ]
        # print(model_list)
        # Respond with the list of available generative models
        json_response = {
            'status': 'success',
            'message': 'List of agents retrieved successfully',
            'agent_list': agent_list,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#get /models :: get the list of available generative model
@app.get("/models")
async def get_model_list(redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Get the list of model IDs
        
        model_ids = redis.keys("model:*:name")
        # print(model_ids)
        # return JSONResponse(content=model_ids, status_code=200)
        # Extract model information (ID and name) from Redis
        model_list = [{"model_id": int(model_id.split(b':')[1]), "model_name": ( redis.get(model_id)).decode('ascii')} for model_id in model_ids]
        # print(model_list)
        # Respond with the list of available generative models
        json_response = {
            'status': 'success',
            'message': 'List of available generative models retrieved successfully',
            'model_list': model_list,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
# le prochain endpoint est:
# get /agents/{agent_id} :: get agent information by id
# la reponse doit suivre le format de reponse json que nous utilisons depuis, et doit inclure le nom, l'id la desciption, ainsi que le model(nom et id)
@app.get("/agents/{agent_id}")
async def get_agent_info(agent_id: str = Path(..., description="Agent ID") ,redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Get the list of model IDs
        agent_name = redis.get(f"agent:{agent_id}:name")
        if agent_name is None:
            json_response = {
                'status': 'fail',
                'message': f'Agent doesn\'t exist',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)
        agent_name = agent_name.decode('ascii')
        agent_description = redis.get(f"agent:{agent_id}:description").decode('ascii')
        model_id = redis.get(f"agent:{agent_id}:model").decode('ascii')
        model_name = redis.get(f"model:{model_id}:name").decode('ascii')
        model = {'model_id': int(model_id), "model_name": model_name}
        
        # Respond with the list of available generative models
        json_response = {
            'status': 'success',
            'message': 'Agent\'s informations retrieved successfully',
            'agent_id': agent_id,
            'agent_name': agent_name,
            'agent_description': agent_description,
            'model': model,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#put /agents/{agent_id}/model/{model_id}  :: Modify the model used by the agent
@app.put("/agents/{agent_id}/model/{model_id}")
async def update_agent_model(agent_id: str = Path(..., description="Agent ID"), model_id: str = Path(..., description="Model ID") ,redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Get the list of model IDs
        agent_name = redis.get(f"agent:{agent_id}:name")
        if agent_name is None:
            json_response = {
                'status': 'fail',
                'message': f'Agent doesn\'t exist',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)
        model_name = redis.get(f"model:{model_id}:name")
        if model_name is None:
            json_response = {
                'status': 'fail',
                'message': f'Model doesn\'t exist',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)
        redis.set(f"agent:{agent_id}:model", model_id)
        
        # Respond with the list of available generative models
        json_response = {
            'status': 'success',
            'message': 'Agent\'s informations retrieved successfully',
            'agent_id': agent_id,
            'agent_name': agent_name.decode('ascii'),
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#delete /agents/{agent_id} :: Delete the agent {agent_id}
@app.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str = Path(..., description="Agent ID"), redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Check if the agent exists
        agent_name =  await redis.get(f"agent:{agent_id}:name")
        if agent_name is None:
            # Return a JSON response for 404 if the agent doesn't exist
            json_response = {
                'status': 'fail',
                'message': 'Agent doesn\'t exist',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Delete agent information from Redis
        await redis.delete(f"agent:{agent_id}:name")
        await redis.delete(f"agent:{agent_id}:description")
        await redis.delete(f"agent:{agent_id}:model")

        # Respond with success
        json_response = {
            'status': 'success',
            'message': f'Agent {agent_id} deleted successfully',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a JSON response for 500 in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

#post /agents/{agent_id}/message  :: talk to the agent    
@app.post("/agents/{agent_id}/message")
async def talk_to_agent(agent_id: str = Path(..., description="Agent ID"),
                        message: str = Form(..., description="Message"),
                        user_id: str = Form(..., description="User ID"),
                        redis: aioredis.Redis = Depends(get_redis)):
    try:
        # Check if the agent exists
        agent_name = await redis.get(f"agent:{agent_id}:name")
        if agent_name is None:
            # Return a JSON response for 404 if the agent doesn't exist
            json_response = {
                'status': 'fail',
                'message': 'Agent doesn\'t exist',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        # Get the current message counter for the agent and user
        message_counter = await redis.incr(f"agent:{agent_id}:user:{user_id}:message_counter")

        # Store the message in Redis with a key that includes the user identifier
        await redis.rpush(f"agent:{agent_id}:user:{user_id}:messages", message)

        # Call a function to get the agent's response based on the received message
        agent_response = get_agent_response(message)

        # Store the response in Redis along with the message counter and user identifier
        await redis.set(f"agent:{agent_id}:user:{user_id}:response:{message_counter}", agent_response)

        # Respond with success along with the agent's response
        json_response = {
            'status': 'success',
            'message': 'Message sent to agent successfully',
            'response': agent_response,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        # Return a JSON response for 500 in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)
    
@app.get("/agents/{agent_id}/history_message/{user_id}")
async def get_user_history(agent_id: str = Path(..., description="Agent ID"), 
                           user_id: str = Path(..., description="User ID"),
                           redis: aioredis.Redis = Depends(get_redis)):
    try:
        history = await get_message_history(agent_id, user_id, redis)

        if history is None:
            json_response = {
                'status': 'fail',
                'message': 'No history available for the user',
                'status_code': 404,
            }
            return JSONResponse(content=json_response, status_code=404)

        json_response = {
            'status': 'success',
            'message': 'Message and response history retrieved successfully',
            'agent_id': agent_id,
            'user_id': user_id,
            'history': history,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


@app.post("/alphaTester/{email}/{password}", response_model=dict)
async def add_alpha_tester(
    email: str = Path(..., description="Email of the alpha tester"),
    password: str = Path(..., description="Password of the alpha tester"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Check if the email already exists
        alpha_tester_ids = await redis.keys("alphaTester:*:email")
        for alpha_tester_id_key in alpha_tester_ids:
            stored_email = await redis.get(alpha_tester_id_key)
            if stored_email.decode('utf-8') == email:
                raise HTTPException(status_code=400, detail="Email already exists")

        # Increment alpha tester ID
        alpha_tester_id = await redis.incr("global:alpha_tester_id")

        # Store email and password in Redis
        await redis.set(f"alphaTester:{alpha_tester_id}:email", email)
        await redis.set(f"alphaTester:{alpha_tester_id}:password", password)

        # Respond with success and the assigned alpha tester ID
        json_response = {
            'status': 'success',
            'message': f'Alpha tester {email} added successfully',
            'alpha_tester_id': alpha_tester_id,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


@app.get("/alphaTester/emailExists/{email}", response_model=dict)
async def check_alpha_tester_email_exist(
    email: str = Path(..., description="Email to check"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Get all alpha tester IDs
        alpha_tester_ids = await redis.keys("alphaTester:*:email")

        # Iterate through alpha tester IDs to check if email exists
        email_exists = False
        for alpha_tester_id in alpha_tester_ids:
            stored_email = await redis.get(alpha_tester_id)
            if stored_email.decode('utf-8') == email:
                email_exists = True
                break

        # Respond with a boolean indicating if the email exists
        json_response = {
            'email': email,
            'exists': email_exists,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)

@app.get("/alphaTester/{email}/{password}", response_model=dict)
async def check_alpha_tester_credentials(
    email: str = Path(..., description="Email of the alpha tester"),
    password: str = Path(..., description="Password to check"),
    redis: aioredis.Redis = Depends(get_redis),
):
    '''
        Verify email and password match
    '''
    try:
        # Get all alpha tester IDs
        alpha_tester_ids = await redis.keys("alphaTester:*:email")

        # Iterate through alpha tester IDs to check credentials
        email_exists = False
        password_match = False
        alpha_tester_id = None
        for alpha_tester_id_key in alpha_tester_ids:
            stored_email = await redis.get(alpha_tester_id_key)
            if stored_email.decode('utf-8') == email:
                email_exists = True
                alpha_tester_id = alpha_tester_id_key.decode("utf-8").split(":")[1]
                stored_password = await redis.get(f"alphaTester:{alpha_tester_id}:password")
                print(stored_password)
                if stored_password.decode('utf-8') == password:
                    password_match = True
                break

        # Respond with a boolean indicating if the credentials match
        json_response = {
            'email': email,
            'password_match': password_match,
            'alpha_tester_id': alpha_tester_id,
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)


@app.delete("/alphaTester/{email}", response_model=dict)
async def delete_alpha_tester(
    email: str = Path(..., description="Email of the alpha tester to delete"),
    redis: aioredis.Redis = Depends(get_redis),
):
    try:
        # Get the alpha tester ID associated with the email
        alpha_tester_ids = await redis.keys("alphaTester:*:email")
        alpha_tester_id = None
        for alpha_tester_id_key in alpha_tester_ids:
            stored_email = await redis.get(alpha_tester_id_key)
            if stored_email.decode('utf-8') == email:
                alpha_tester_id = alpha_tester_id_key.decode('utf-8').split(":")[1]
                break

        # Check if the alpha tester ID exists
        if alpha_tester_id is None:
            raise HTTPException(status_code=404, detail="Alpha tester not found")

        # Delete the alpha tester data from Redis
        await redis.delete(f"alphaTester:{alpha_tester_id}:email")
        await redis.delete(f"alphaTester:{alpha_tester_id}:password")

        # Respond with success message
        json_response = {
            'status': 'success',
            'message': f'Alpha tester with email {email} deleted successfully',
            'status_code': 200,
        }
        return JSONResponse(content=json_response, status_code=200)

    except Exception as e:
        print(e)
        # Return a generic error response in case of unexpected errors
        json_response = {
            'status': 'fail',
            'message': str(e),
            'status_code': 500,
        }
        return JSONResponse(content=json_response, status_code=500)