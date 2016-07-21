package controllers

import play.api._
import play.api.mvc._
import play.api.data._
import play.api.data.Forms._
import views._

object AuthenticationController extends AuthenticationController

class AuthenticationController extends Controller {

  val loginForm = Form(
    tuple(
      "email" -> text,
      "password" -> text
    )
  )

  /**
    * Login page.
    */
  def login = Action { implicit request =>
    Ok(views.html.login(loginForm))
  }

  /**
    * Logout and clean the session.
    */
  def logout = Action {
    Redirect(routes.AuthenticationController.login).withNewSession.flashing(
      "success" -> "You've been logged out"
    )
  }

  /**
    * Handle login form submission.
    */
  def authenticate = Action { implicit request =>
    loginForm.bindFromRequest.fold(
      formWithErrors => BadRequest(views.html.login(formWithErrors)),
      user => Ok(views.html.restricted())
    )
  }

}