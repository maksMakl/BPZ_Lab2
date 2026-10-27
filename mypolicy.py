import dataclasses
from accesscontrol.monitor import Decision, Permission, Policy

class Role:
    def __init__(self, name: str) -> None:
        self.name: str = name
        self.permissions: dict[str, Permission] = {}
        self.child_role_names: set[str] = set()

    def grant_permission(self, obj: str, perm: Permission) -> None:
        self.permissions[obj] = self.permissions.get(obj, Permission.NONE) | perm

    def add_child_role(self, child_name: str) -> None:
        self.child_role_names.add(child_name)

    def get_direct_permission(self, obj: str) -> Permission:
        return self.permissions.get(obj, Permission.NONE)

@dataclasses.dataclass
class Delegation:
    delegator: str
    delegatee: str
    obj: str
    perm: Permission
    depth: int

class VariantPolicy(Policy):
    def __init__(self) -> None:
        self.user_roles: dict[str, set[str]] = {}
        self.roles: dict[str, Role] = {}
        self.delegations: dict[str, list[Delegation]] = {}

    def grant(self, role_name: str, obj: str, perm: Permission) -> None:
        if role_name not in self.roles:
           raise Exception("Role name {} not found.".format(role_name))
        role = self.roles[role_name]
        role.grant_permission(obj, perm)

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        subject_permissions = self.get_all_permissions_for_user(subject)
        effective = subject_permissions.get(obj, Permission.NONE)
        for d in self.delegations.get(subject, []):
            if d.obj == obj:
                effective |= d.perm
        if action & effective == action:
            return Decision(True, "надано")

        return Decision(False, "явного дозволу немає (safe default)")

    def add_role(self, role: Role) -> None:
        self.roles[role.name] = role

    def assign_role(self, subject: str, role_name: str) -> None:
        if subject not in self.user_roles:
            self.user_roles[subject] = set()
        self.user_roles[subject].add(role_name)

    def get_all_roles_for_user(self, subject: str) -> set[Role]:
        visited = set()
        stack = list(self.user_roles.get(subject, set()))
        result = set()

        while stack:
            role_name = stack.pop()
            if role_name in visited:
                continue
            visited.add(role_name)

            role = self.roles.get(role_name)
            if role:
                result.add(role)
                stack.extend(role.child_role_names)

        return result

    def get_all_permissions_for_user(self, subject: str) -> dict[str, Permission]:
        total_permissions: dict[str, Permission] = {}
        user_roles = self.get_all_roles_for_user(subject)

        for role in user_roles:
            for obj, perm in role.permissions.items():
                total_permissions[obj] = total_permissions.get(obj, Permission.NONE) | perm

        return total_permissions

    def delegate(self, delegator: str, delegatee: str, obj: str, perm: Permission, requested_depth: int) -> None:
        if requested_depth < 0:
            raise Exception("Requested depth cannot be negative.")

        delegator_original_permissions = self.get_all_permissions_for_user(delegator)
        if delegator_original_permissions.get(obj, Permission.NONE) & perm == perm:
            if delegatee not in self.delegations:
                self.delegations[delegatee] = []
            self.delegations[delegatee].append(Delegation(delegator, delegatee, obj, perm, requested_depth))
            return
        else:
            delegator_delegated_permissions = self.delegations.get(delegator, [])
            for delegation in delegator_delegated_permissions:
                if delegation.obj == obj and delegation.perm & perm == perm:
                    if requested_depth >= delegation.depth:
                        continue

                    if delegatee not in self.delegations:
                        self.delegations[delegatee] = []
                    self.delegations[delegatee].append(Delegation(delegator, delegatee, obj, perm, requested_depth))
                    return

        raise Exception("Delegation not allowed: insufficient depth or missing permission.")

    def get_effective_permissions_for_user(self, subject: str) -> dict[str, Permission]:
        perms = self.get_all_permissions_for_user(subject)
        for d in self.delegations.get(subject, []):
            perms[d.obj] = perms.get(d.obj, Permission.NONE) | d.perm
        return perms

    def objects_accessible_by(self, subject: str, action: Permission) -> set[str]:
        effective_map = self.get_effective_permissions_for_user(subject)
        return {
            obj for obj, perm in effective_map.items()
            if (perm & action) == action
        }

    def subjects_with_access(self, obj: str, action: Permission) -> set[str]:
        all_known_subjects = set(self.user_roles.keys()) | set(self.delegations.keys())
        return {
            sub for sub in all_known_subjects
            if self.evaluate(sub, obj, action).allowed
        }



def create_populated_policy() -> tuple[VariantPolicy, list[str], list[str]]:
    policy = VariantPolicy()

    documents = [f"doc_{i}" for i in range(1, 11)]
    reports = [f"report_{i}" for i in range(1, 6)]
    systems = [f"system_{i}" for i in range(1, 6)]
    all_objects = documents + reports + systems

    subjects = ["alice", "bob", "charlie", "dave", "eve", "frank", "grace"]

    viewer = Role("viewer")
    editor = Role("editor")
    manager = Role("manager")
    auditor = Role("auditor")
    admin = Role("admin")

    editor.add_child_role("viewer")
    manager.add_child_role("editor")

    for role in [viewer, editor, manager, auditor, admin]:
        policy.add_role(role)


    for doc in documents:
        policy.grant("viewer", doc, Permission.READ)

    for doc in documents[:5]:
        policy.grant("editor", doc, Permission.WRITE)

    for doc in documents[:5]:
        policy.grant("manager", doc, Permission.DELETE)
    for rep in reports:
        policy.grant("manager", rep, Permission.READ | Permission.WRITE | Permission.DELETE)

    for sys in systems:
        policy.grant("auditor", sys, Permission.READ)

    for sys in systems:
        policy.grant("admin", sys, Permission.READ | Permission.WRITE | Permission.DELETE | Permission.ADMIN)


    policy.assign_role("alice", "manager")
    policy.assign_role("bob", "editor")
    policy.assign_role("bob", "auditor")
    policy.assign_role("charlie", "viewer")
    policy.assign_role("dave", "auditor")
    policy.assign_role("eve", "admin")
    policy.assign_role("frank", "editor")
    policy.assign_role("grace", "viewer")

    return policy, subjects, all_objects