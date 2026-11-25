// Intentionally vulnerable training app: these are the application's own bugs, for a
// SAST tool to report. Kodand must not, because nothing here is agent content.
import { exec } from 'child_process'
const adminPassword = 'admin123!Secret'
export function login (user: string) {
  exec('grep ' + user + ' /etc/passwd')
  return eval('user.length')
}
