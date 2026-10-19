export const permissions = {
  admin: ["read", "edit", "members", "policy", "audit", "devices"],
  member: ["read", "edit"],
  viewer: ["read"],
} as const;
export type Role = keyof typeof permissions;
export type Action = (typeof permissions.admin)[number];
export function can(role: Role, action: Action): boolean {
  return (permissions[role] as readonly string[]).includes(action);
}
