import os

def create_workspace_instance(base_name="project_run"):
    workspace_dir = "workspace"
    os.makedirs(workspace_dir, exist_ok=True)
    
    instance_path = os.path.join(workspace_dir, base_name)
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        return instance_path
    counter = 1
    while True:
        new_path = os.path.join(workspace_dir, f"{base_name}_{counter}")
        if not os.path.exists(new_path):
            os.makedirs(new_path)
            return new_path
        counter += 1