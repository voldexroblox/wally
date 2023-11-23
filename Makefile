# define following env variables:
# DOCKER_IMAGE=<Docker image>
# AWS_REGION_NAME=<region>
# AWS_REGION_ENDPOINT=s3.<region>.amazonaws.com
# WALLY_github_token=<PAT from Github for private repo over SSH>
# WALLY_auth=<api_key json string>


#build and push
.PHONY: docker
docker: DOCKERX86 DOCKERPUSH

#build for x86. required on mac
.PHONY: DOCKERX86
DOCKERX86:
	docker buildx build --platform=linux/amd64 -t ${DOCKER_IMAGE}  -f wally-registry-backend/Dockerfile .

.PHONY: DOCKERPUSH
DOCKERPUSH:
	docker push ${DOCKER_IMAGE} 

#run wally locally in docker
.PHONEY: drun
drun:
	docker build -t ${DOCKER_IMAGE} -f wally-registry-backend/Dockerfile . && \
	docker run -p 8000:8000 \
	--env AWS_REGION_NAME=${AWS_REGION_NAME} --env AWS_REGION_ENDPOINT=${AWS_REGION_ENDPOINT} ${DOCKER_IMAGE} 
	--env WALLY_auth=${WALLY_auth} --env WALLY_github_token=${WALLY_github_token} \
	
.PHONY: clean
clean:
	rm -rf target
