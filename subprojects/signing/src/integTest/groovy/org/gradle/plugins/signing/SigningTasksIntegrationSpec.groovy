/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gradle.plugins.signing

import org.gradle.integtests.fixtures.executer.GradleContextualExecuter
import org.gradle.plugins.signing.signatory.internal.gnupg.GnupgSignatoryProvider
import org.gradle.plugins.signing.signatory.pgp.PgpSignatoryProvider
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.gradle.plugins.signing.SigningIntegrationSpec.SignMethod.GPG_CMD

class SigningTasksIntegrationSpec extends SigningIntegrationSpec {

    @IgnoreIf({GradleContextualExecuter.parallel})
    def "sign jar with default signatory"() {
        given:
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}

            signing {
                ${signingConfiguration()}
                sign jar
            }
        """

        when:
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        and:
        file("build", "libs", "sign-1.0.jar.asc").text

        when:
        run "signJar"

        then:
        ":signJar" in skippedTasks
    }

    @IgnoreIf({GradleContextualExecuter.parallel})
    def "sign multiple jars with default signatory"() {
        given:
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            ${javadocAndSourceJarsScript}

            signing {
                ${signingConfiguration()}
                sign jar, javadocJar, sourcesJar
            }
        """

        when:
        run "signJar", "signJavadocJar", "signSourcesJar"

        then:
        [":signJar", ":signJavadocJar", ":signSourcesJar"].every { it in nonSkippedTasks }

        and:
        file("build", "libs", "sign-1.0.jar.asc").text
        file("build", "libs", "sign-1.0-javadoc.jar.asc").text
        file("build", "libs", "sign-1.0-sources.jar.asc").text

        when:
        run "signJar", "signJavadocJar", "signSourcesJar"

        then:
        [":signJar", ":signJavadocJar", ":signSourcesJar"].every { it in skippedTasks }
    }

    def "out-of-date when signatory changes"() {
        given:
        def originalSignMethod = signMethod
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            signing {
                ${signingConfiguration()}
                sign(jar)
            }
        """

        when:
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        when:
        if (originalSignMethod != GPG_CMD) {
            setupGpgCmd()
        }
        def signatoryProviderClass = originalSignMethod != GPG_CMD ? GnupgSignatoryProvider : PgpSignatoryProvider
        buildFile << """
            signing {
                signatories = new ${signatoryProviderClass.name}()
            }
        """
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        when:
        run "signJar"

        then:
        ":signJar" in skippedTasks
    }

    def "out-of-date when signatureType changes"() {
        given:
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            signing {
                ${signingConfiguration()}
                sign(jar)
            }
        """

        when:
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        when:
        setupGpgCmd()
        buildFile << """
            signing {
                signatureTypes.defaultType = 'sig'
            }
        """
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        when:
        run "signJar"

        then:
        ":signJar" in skippedTasks
    }

    def "out-of-date when input file changes"() {
        given:
        def inputFile = file("input.txt")
        inputFile.text = "foo"
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            signing {
                ${signingConfiguration()}
            }
            task signCustomFile(type: Sign) {
                sign(file("input.txt"))
            }
        """

        when:
        run "signCustomFile"

        then:
        ":signCustomFile" in nonSkippedTasks
        file("input.txt.asc").exists()

        when:
        inputFile.text = "bar"
        run "signCustomFile"

        then:
        ":signCustomFile" in nonSkippedTasks

        when:
        run "signCustomFile"

        then:
        ":signCustomFile" in skippedTasks
    }

    def "out-of-date when output file is deleted"() {
        given:
        def inputFile = file("input.txt")
        inputFile.text = "foo"
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            signing {
                ${signingConfiguration()}
            }
            task signCustomFile(type: Sign) {
                sign(file("input.txt"))
            }
        """

        when:
        run "signCustomFile"

        then:
        ":signCustomFile" in nonSkippedTasks
        def outputFile = file("input.txt.asc")
        outputFile.exists()

        when:
        outputFile.delete()
        run "signCustomFile"

        then:
        ":signCustomFile" in nonSkippedTasks

        when:
        run "signCustomFile"

        then:
        ":signCustomFile" in skippedTasks
    }

    @Unroll
    def "emits deprecation warning when Sign.#method is used"() {
        given:
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}
            signing {
                ${signingConfiguration()}
                sign jar
            }
            signJar.doLast {
                println $method
            }
        """

        when:
        executer.expectDeprecationWarning()
        succeeds("signJar")

        then:
        outputContains("The Sign.$method method has been deprecated")

        where:
        method << ["getInputFiles()", "getOutputFiles()"]
    }

    def "trying to sign a task that isn't an archive task gives nice enough message"() {
        given:
        buildFile << """
            signing {
                ${signingConfiguration()}
                sign clean
            }
        """

        when:
        runAndFail "signClean"

        then:
        failureHasCause "You cannot sign tasks that are not 'archive' tasks, such as 'jar', 'zip' etc. (you tried to sign task ':clean')"
    }

    @IgnoreIf({GradleContextualExecuter.parallel})
    def "changes to task information after signing block are respected"() {
        given:
        buildFile << """
            ${keyInfo.addAsPropertiesScript()}

            signing {
                ${signingConfiguration()}
                sign jar
            }

            jar {
                baseName = "changed"
                classifier = "custom"
            }
        """

        when:
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        and:
        file("build", "libs", "changed-1.0-custom.jar.asc").text

    }

    @IgnoreIf({GradleContextualExecuter.parallel})
    def "sign with subkey"() {
        given:
        buildFile << """
            ${getKeyInfo("subkey").addAsPropertiesScript()}

            signing {
                sign jar
            }
        """

        when:
        run "signJar"

        then:
        ":signJar" in nonSkippedTasks

        and:
        file("build", "libs", "sign-1.0.jar.asc").text
    }
}
