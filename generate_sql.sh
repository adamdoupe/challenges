#!/usr/bin/env bash

CATEGORIES=("babyshell" "babyjail" "babyrev" "babymem" "toddler1" "babyrop" "babykernel" "babyheap" "babyrace" "toddler2" "babyauto")

id=1
for category in ${CATEGORIES[@]}; do
    for challenge in $(ls -v $category | grep -v '.*\.c'); do
        path="$category/$challenge"
        if [ -d "$path" ]; then
            docker_image="pwncollege_kernel_challenge"
        elif echo $path | grep -q '.*\.ko'; then
            docker_image="pwncollege_kernel_challenge"
        else
            docker_image="pwncollege_challenge"
        fi
        echo "insert into challenges (id, name, description, max_attempts, value, category, type, state) values (${id}, '${challenge}', '', 0, 1, '${category}', 'docker', 'visible');"
        echo "insert into docker_challenges (id, docker_image_name) values (${id}, '${docker_image}');"
        echo "insert into flags (id, challenge_id, type, content, data) values (${id}, ${id}, 'user', '', 'cheater');"
        id=$((id+1))
    done
done
