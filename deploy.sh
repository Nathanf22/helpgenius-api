gcloud run deploy \
--image gcr.io/llm-agent-414413/helpgenius-api \
--platform managed \
--allow-unauthenticated \
--region us-central1 \
--vpc-connector redis-vpc \
--set-env-vars REDISHOST=10.230.158.115,REDISPORT=6379