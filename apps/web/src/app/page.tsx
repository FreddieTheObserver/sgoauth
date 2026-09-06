import { redirect } from "next/navigation";
import { getSession, LOGIN_PATH } from "@/lib/dal";

// There is no landing page to show: this app is a login and the thing behind it.
// Deciding here rather than redirecting to /dashboard and letting that bounce
// keeps a signed-out visitor to one hop.
export default async function Home() {
  const user = await getSession();
  redirect(user ? "/dashboard" : LOGIN_PATH);
}
